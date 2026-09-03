import tempfile
import unittest
from pathlib import Path

from detection_engine.database import insert_alerts
from detection_engine.engine import create_alert, database_events
from detection_engine.loader import load_rule
from incidents.database import persist_incidents
from incidents.engine import correlate, load_alerts
from ingestion.database import connect, insert_events
from response.actions import approve_action, create_action, simulate_action, transition_incident
from response.database import trace_action

ROOT = Path(__file__).parents[2]


class ResponseGoldenPathTests(unittest.TestCase):
    def test_event_to_simulated_containment_and_incident_state(self):
        event = {
            "timestamp": "2026-09-03T13:00:00Z", "event_id": 10,
            "event_record_id": "42", "record_index": 1, "computer": "FIN-WS01",
            "username": r"WESTBRIDGE\jsmith", "process_name": None,
            "parent_process": None, "command_line": None, "source_ip": None,
            "source": "Microsoft-Windows-Sysmon/Operational",
            "provider": "Microsoft-Windows-Sysmon", "dataset": "EVTX-ATTACK-SAMPLES",
            "source_file": "Credential Access/golden.evtx", "source_category": "Credential Access",
            "attack_technique": "T1003.001", "attack_technique_name": "LSASS Memory",
            "attack_tactic": "Credential Access", "curated_technique_id": "T1003.001",
            "curated_technique_name": "LSASS Memory", "curated_by": "Project analyst",
            "curated_at": "2026-09-03", "mapping_rationale": "Golden mapping",
            "upstream_techniques": [],
            "event_data": {"TargetImage": r"C:\Windows\System32\lsass.exe",
                           "SourceImage": "powershell.exe", "GrantedAccess": "0x1010"},
            "raw_xml": "<Event><TargetImage>lsass.exe</TargetImage></Event>",
        }
        with tempfile.TemporaryDirectory() as directory:
            connection = connect(Path(directory) / "events.db")
            insert_events(connection, [event])
            stored = database_events(connection)[0]
            rule = load_rule(ROOT / "detection_engine/rules/det-003-lsass-process-access.yaml")
            alert = create_alert(stored, rule, "2026-09-03T13:01:00Z")
            insert_alerts(connection, [alert])
            incident = correlate(load_alerts(connection), recorded_at="2026-09-03T13:02:00Z")[0]
            persist_incidents(connection, [incident])
            transition_incident(connection, incident.incident_id, "TRIAGING")
            transition_incident(connection, incident.incident_id, "INVESTIGATING")
            action, _ = create_action(
                connection, incident.incident_id, "ISOLATE_HOST", "FIN-WS01",
                "Isolate the endpoint because LSASS access may expose credentials.",
                "Project analyst", [alert.alert_id], "2026-09-03T13:03:00Z")
            approve_action(connection, action.action_id, "2026-09-03T13:04:00Z")
            completed = simulate_action(connection, action.action_id, "2026-09-03T13:05:00Z")
            traced = trace_action(connection, action.action_id)
            incident_status = connection.execute(
                "SELECT status FROM incidents WHERE incident_id = ?", (incident.incident_id,)).fetchone()[0]
            connection.close()
        self.assertEqual("SIMULATED", completed.status)
        self.assertEqual("CONTAINED", incident_status)
        self.assertEqual(alert.alert_id, traced["evidence"][0]["alert_id"])
        self.assertEqual("EVTX-ATTACK-SAMPLES", traced["evidence"][0]["dataset"])
        self.assertIn("lsass.exe", traced["evidence"][0]["raw_xml"])


if __name__ == "__main__":
    unittest.main()
