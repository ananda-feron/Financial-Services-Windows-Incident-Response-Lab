import json
import tempfile
import unittest
from pathlib import Path

from detection_engine.database import insert_alerts
from detection_engine.engine import create_alert, database_events
from detection_engine.loader import load_rule
from incidents.database import persist_incidents
from incidents.engine import correlate, load_alerts
from ingestion.database import connect, insert_events
from ioc.database import persist_observations
from ioc.extractor import extract_incident
from metrics.__main__ import collect
from metrics.attack_coverage import attack_coverage
from metrics.detection_metrics import detection_metrics, detection_performance, load_ground_truth
from metrics.incident_metrics import incident_metrics, provenance_metrics, response_metrics
from response.actions import approve_action, create_action, simulate_action, transition_incident

ROOT = Path(__file__).parents[2]
RULES = ROOT / "detection_engine" / "rules"


def normalized_event():
    return {
        "timestamp": "2026-09-03T13:00:00Z", "event_id": 10,
        "event_record_id": "42", "record_index": 1, "computer": "FIN-WS01",
        "username": r"WESTBRIDGE\jsmith", "process_name": None,
        "parent_process": None, "command_line": None, "source_ip": None,
        "source": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon", "dataset": "TEST-DATASET",
        "source_file": "Credential Access/golden.evtx", "source_category": "Credential Access",
        "attack_technique": "T1003.001", "attack_technique_name": "LSASS Memory",
        "attack_tactic": "Credential Access", "curated_technique_id": "T1003.001",
        "curated_technique_name": "LSASS Memory", "curated_by": "Project analyst",
        "curated_at": "2026-09-03", "mapping_rationale": "Golden mapping",
        "upstream_techniques": [],
        "event_data": {"TargetImage": r"C:\Windows\System32\lsass.exe",
                       "SourceImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                       "GrantedAccess": "0x00001010", "Hashes": "SHA256=" + "a" * 64},
        "raw_xml": "<Event><TargetImage>lsass.exe</TargetImage></Event>",
    }


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        directory = Path(self.directory.name)
        self.connection = connect(directory / "events.db")
        self.manifest = directory / "ground_truth.json"
        self.manifest.write_text(json.dumps({
            "samples": [{"source_file": "Credential Access/golden.evtx",
                         "technique_id": "T1003.001", "expected_detections": ["DET-003"]}]
        }), encoding="utf-8")

    def tearDown(self):
        self.connection.close()
        self.directory.cleanup()

    def build_pipeline(self):
        insert_events(self.connection, [normalized_event()])
        event = database_events(self.connection)[0]
        rule = load_rule(RULES / "det-003-lsass-process-access.yaml")
        alert = create_alert(event, rule, "2026-09-03T13:01:00Z")
        insert_alerts(self.connection, [alert])
        incident = correlate(load_alerts(self.connection), recorded_at="2026-09-03T13:02:00Z")[0]
        persist_incidents(self.connection, [incident])
        persist_observations(self.connection, extract_incident(self.connection, incident.incident_id))
        transition_incident(self.connection, incident.incident_id, "TRIAGING")
        transition_incident(self.connection, incident.incident_id, "INVESTIGATING")
        action, _ = create_action(
            self.connection, incident.incident_id, "ISOLATE_HOST", "FIN-WS01",
            "Contain credential-access activity.", "Project analyst", [alert.alert_id])
        approve_action(self.connection, action.action_id)
        simulate_action(self.connection, action.action_id)
        return incident, alert, action

    def test_event_alert_and_rule_evaluation_counts(self):
        self.build_pipeline()
        result = detection_metrics(self.connection, RULES)
        self.assertEqual(1, result["events_analyzed"])
        self.assertEqual(3, result["enabled_rules"])
        self.assertEqual(3, result["rules_evaluated"])
        self.assertEqual(1, result["alerts_generated"])

    def test_alert_aggregations(self):
        self.build_pipeline()
        result = detection_metrics(self.connection, RULES)
        self.assertEqual({"critical": 1}, result["alerts_by_severity"])
        self.assertEqual({"DET-003": 1}, result["alerts_by_detection"])

    def test_ground_truth_matches_actual_detection(self):
        self.build_pipeline()
        result = detection_performance(self.connection, self.manifest)
        self.assertEqual(1, result["matched_detections"])
        self.assertEqual([], result["missed_detections"])
        self.assertEqual([], result["unexpected_detections"])
        self.assertEqual(1.0, result["recall"])
        self.assertIsNone(result["precision"])

    def test_ground_truth_reports_missed_and_unexpected(self):
        self.build_pipeline()
        self.manifest.write_text(json.dumps({
            "samples": [{"source_file": "Credential Access/golden.evtx",
                         "technique_id": "T1047", "expected_detections": ["DET-002"]}]
        }), encoding="utf-8")
        result = detection_performance(self.connection, self.manifest)
        self.assertEqual(1, len(result["missed_detections"]))
        self.assertEqual(1, len(result["unexpected_detections"]))

    def test_attack_coverage_uses_labeled_telemetry(self):
        self.build_pipeline()
        result = attack_coverage(self.connection, RULES, self.manifest)
        row = next(item for item in result["techniques"] if item["technique_id"] == "T1003.001")
        self.assertTrue(row["observed_in_labeled_telemetry"])
        self.assertTrue(row["enabled_rule_exists"])
        self.assertTrue(row["detected"])
        self.assertEqual(100.0, result["coverage_percent"])

    def test_incident_and_relationship_averages(self):
        self.build_pipeline()
        result = incident_metrics(self.connection)
        self.assertEqual(1, result["total_incidents"])
        self.assertEqual({"critical": 1}, result["incidents_by_severity"])
        self.assertEqual(1.0, result["alerts_per_incident"])
        self.assertGreater(result["iocs_per_incident"], 0)
        self.assertEqual(1.0, result["response_actions_per_incident"])

    def test_response_statistics(self):
        self.build_pipeline()
        result = response_metrics(self.connection)
        self.assertEqual(1, result["total_actions"])
        self.assertEqual({"SIMULATED": 1}, result["actions_by_status"])
        self.assertEqual(1, result["containment_actions"])

    def test_provenance_coverage(self):
        self.build_pipeline()
        result = provenance_metrics(self.connection)
        for category in result.values():
            self.assertEqual(100.0, category["percent"])

    def test_empty_dataset_behavior(self):
        detection = detection_metrics(self.connection, RULES)
        incidents = incident_metrics(self.connection)
        provenance = provenance_metrics(self.connection)
        self.assertEqual((0, 0), (detection["events_analyzed"], detection["alerts_generated"]))
        self.assertEqual(0, incidents["total_incidents"])
        self.assertIsNone(provenance["events"]["percent"])

    def test_manifest_validation_and_combined_golden_path(self):
        invalid = Path(self.directory.name) / "invalid.json"
        invalid.write_text('{"samples": {}}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "samples list"):
            load_ground_truth(invalid)
        self.build_pipeline()
        result = collect("all", self.connection, RULES, self.manifest)
        self.assertEqual(1, result["detection"]["alerts_generated"])
        self.assertEqual(1, result["incidents"]["total_incidents"])
        self.assertEqual(100.0, result["coverage"]["coverage_percent"])


if __name__ == "__main__":
    unittest.main()
