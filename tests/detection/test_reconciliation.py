import tempfile
import unittest
from pathlib import Path

from detection_engine.database import insert_alerts, reconcile_alerts
from detection_engine.engine import create_alert, database_events, evaluate
from detection_engine.loader import load_rule
from ingestion.database import connect, insert_events

ROOT = Path(__file__).parents[2]


class ReconciliationTests(unittest.TestCase):
    def test_inconsistent_det003_outcome_becomes_stale(self):
        normalized = {
            "timestamp": "2019-05-11T17:58:54Z", "event_id": 10, "event_record_id": "16118",
            "record_index": 1, "computer": "IEWIN7", "username": None, "process_name": None,
            "parent_process": None, "command_line": None, "source_ip": None,
            "source": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon",
            "dataset": "EVTX-ATTACK-SAMPLES",
            "source_file": "Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx",
            "source_category": "Persistence", "attack_technique": "T1546.003",
            "attack_technique_name": "WMI Event Subscription", "attack_tactic": "Persistence",
            "curated_technique_id": "T1546.003", "curated_technique_name": "WMI Event Subscription",
            "curated_by": "Project analyst", "curated_at": "2026-09-03",
            "mapping_rationale": "Source scenario", "upstream_techniques": [],
            "event_data": {"TargetImage": r"C:\Windows\System32\lsass.exe",
                           "SourceImage": r"C:\python27\python.exe", "GrantedAccess": "0x00001410"},
            "raw_xml": "<Event><SourceImage>python.exe</SourceImage></Event>",
        }
        with tempfile.TemporaryDirectory() as directory:
            connection = connect(Path(directory) / "events.db")
            insert_events(connection, [normalized])
            event = database_events(connection)[0]
            rule = load_rule(ROOT / "detection_engine/rules/det-003-lsass-process-access.yaml")
            self.assertFalse(evaluate(event, rule))
            insert_alerts(connection, [create_alert(event, rule, "2026-09-03T13:00:00Z")])
            reconcile_alerts(connection, [(rule.id, rule.version)], [])
            status = connection.execute("SELECT status FROM alerts").fetchone()[0]
            connection.close()
        self.assertEqual("stale", status)


if __name__ == "__main__": unittest.main()
