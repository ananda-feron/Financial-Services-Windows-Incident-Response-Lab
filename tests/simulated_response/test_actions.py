import tempfile
import unittest
from pathlib import Path

from detection_engine.database import insert_alerts
from detection_engine.engine import create_alert, database_events
from detection_engine.loader import load_rule
from incidents.database import persist_incidents
from incidents.engine import correlate, load_alerts
from ingestion.database import connect, insert_events
from response.actions import (
    approve_action,
    cancel_action,
    create_action,
    simulate_action,
    transition_incident,
)
from response.database import trace_action

ROOT = Path(__file__).parents[2]


def normalized_event():
    return {
        "timestamp": "2026-09-03T13:00:00Z", "event_id": 10,
        "event_record_id": "42", "record_index": 1, "computer": "FIN-WS01",
        "username": r"WESTBRIDGE\jsmith", "process_name": None,
        "parent_process": None, "command_line": None, "source_ip": None,
        "source": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon", "dataset": "EVTX-ATTACK-SAMPLES",
        "source_file": "Credential Access/golden.evtx",
        "source_category": "Credential Access", "attack_technique": "T1003.001",
        "attack_technique_name": "LSASS Memory", "attack_tactic": "Credential Access",
        "curated_technique_id": "T1003.001", "curated_technique_name": "LSASS Memory",
        "curated_by": "Project analyst", "curated_at": "2026-09-03",
        "mapping_rationale": "Golden-path mapping", "upstream_techniques": [],
        "event_data": {"TargetImage": r"C:\Windows\System32\lsass.exe",
                       "SourceImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                       "GrantedAccess": "0x1010"},
        "raw_xml": "<Event><TargetImage>lsass.exe</TargetImage></Event>",
    }


class ResponseActionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.connection = connect(Path(self.directory.name) / "events.db")
        insert_events(self.connection, [normalized_event()])
        event = database_events(self.connection)[0]
        rule = load_rule(ROOT / "detection_engine/rules/det-003-lsass-process-access.yaml")
        alert = create_alert(event, rule, "2026-09-03T13:01:00Z")
        insert_alerts(self.connection, [alert])
        incident = correlate(load_alerts(self.connection), recorded_at="2026-09-03T13:02:00Z")[0]
        persist_incidents(self.connection, [incident])
        self.incident_id = incident.incident_id
        self.alert_id = alert.alert_id

    def tearDown(self):
        self.connection.close()
        self.directory.cleanup()

    def create(self, action_type="ISOLATE_HOST", target="FIN-WS01"):
        return create_action(
            self.connection, self.incident_id, action_type, target,
            "Contain credential-access activity supported by the linked alert.",
            "Project analyst", [self.alert_id], "2026-09-03T13:03:00Z",
        )

    def test_valid_action_is_evidence_backed_and_traceable(self):
        action, created = self.create()
        traced = trace_action(self.connection, action.action_id)
        self.assertTrue(created)
        self.assertEqual("PLANNED", action.status)
        self.assertEqual(self.alert_id, traced["evidence"][0]["alert_id"])
        self.assertEqual("Credential Access/golden.evtx", traced["evidence"][0]["source_file"])
        self.assertIn("lsass.exe", traced["evidence"][0]["raw_xml"])

    def test_invalid_inputs_and_unlinked_evidence_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid response action type"):
            self.create("DELETE_HOST")
        with self.assertRaisesRegex(ValueError, "rationale"):
            create_action(self.connection, self.incident_id, "ISOLATE_HOST", "FIN-WS01",
                          "", "analyst", [self.alert_id])
        with self.assertRaisesRegex(ValueError, "unknown incident"):
            create_action(self.connection, "INC-MISSING", "ISOLATE_HOST", "FIN-WS01",
                          "Reason", "analyst", [self.alert_id])
        with self.assertRaisesRegex(ValueError, "not linked"):
            create_action(self.connection, self.incident_id, "ISOLATE_HOST", "FIN-WS01",
                          "Reason", "analyst", ["ALT-MISSING"])

    def test_duplicate_action_is_idempotent(self):
        first, first_created = self.create()
        second, second_created = self.create()
        count = self.connection.execute("SELECT COUNT(*) FROM response_actions").fetchone()[0]
        evidence_count = self.connection.execute("SELECT COUNT(*) FROM action_evidence").fetchone()[0]
        self.assertTrue(first_created)
        self.assertFalse(second_created)
        self.assertEqual(first.action_id, second.action_id)
        self.assertEqual((1, 1), (count, evidence_count))

    def test_approved_simulation_contains_investigating_incident(self):
        action, _ = self.create()
        transition_incident(self.connection, self.incident_id, "TRIAGING")
        transition_incident(self.connection, self.incident_id, "INVESTIGATING")
        approve_action(self.connection, action.action_id, "2026-09-03T13:04:00Z")
        result = simulate_action(self.connection, action.action_id, "2026-09-03T13:05:00Z")
        incident_status = self.connection.execute(
            "SELECT status FROM incidents WHERE incident_id = ?", (self.incident_id,)).fetchone()[0]
        self.assertEqual("SIMULATED", result.status)
        self.assertEqual("CONTAINED", incident_status)

    def test_collect_artifact_does_not_imply_containment(self):
        action, _ = self.create("COLLECT_ARTIFACT", "FIN-WS01:memory")
        transition_incident(self.connection, self.incident_id, "TRIAGING")
        transition_incident(self.connection, self.incident_id, "INVESTIGATING")
        approve_action(self.connection, action.action_id)
        simulate_action(self.connection, action.action_id)
        status = self.connection.execute(
            "SELECT status FROM incidents WHERE incident_id = ?", (self.incident_id,)).fetchone()[0]
        self.assertEqual("INVESTIGATING", status)

    def test_invalid_transitions_and_unapproved_simulation_are_rejected(self):
        action, _ = self.create()
        with self.assertRaisesRegex(ValueError, "PLANNED -> SIMULATED"):
            simulate_action(self.connection, action.action_id)
        with self.assertRaisesRegex(ValueError, "NEW -> CONTAINED"):
            transition_incident(self.connection, self.incident_id, "CONTAINED", action_id=action.action_id)
        cancelled = cancel_action(self.connection, action.action_id)
        self.assertEqual("CANCELLED", cancelled.status)


if __name__ == "__main__":
    unittest.main()
