import sqlite3
import tempfile
import unittest
from pathlib import Path

from detection_engine.database import insert_alerts, trace_alert
from detection_engine.engine import create_alert, database_events, evaluate
from detection_engine.loader import load_rule
from ingestion.database import connect, insert_events

ROOT = Path(__file__).parents[2]


class DetectionGoldenPathTests(unittest.TestCase):
    def test_event_to_rule_to_alert_to_source_trace(self):
        normalized = {
            "timestamp": "2026-09-03T12:00:00Z", "event_id": 1,
            "event_record_id": "42", "record_index": 1, "computer": "FIN-WS01",
            "username": r"WESTBRIDGE\jsmith",
            "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_process": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
            "command_line": "powershell.exe -NoP Get-Process", "source_ip": None,
            "source": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon",
            "dataset": "EVTX-ATTACK-SAMPLES", "source_file": "Execution/example.evtx",
            "source_category": "Execution", "attack_technique": "T1059.001",
            "attack_technique_name": "PowerShell", "attack_tactic": "Execution",
            "curated_technique_id": "T1059.001", "curated_technique_name": "PowerShell",
            "curated_by": "Project analyst", "curated_at": "2026-09-03",
            "mapping_rationale": "Validated test mapping",
            "upstream_techniques": [{"id": "T1086", "name": "PowerShell"}],
            "event_data": {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
            "raw_xml": "<Event>preserved evidence</Event>",
        }
        rule = load_rule(ROOT / "detection_engine" / "rules" / "det-001-suspicious-powershell.yaml")
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            connection = connect(database)
            self.assertEqual((1, 0), insert_events(connection, [normalized]))
            stored = database_events(connection)[0]
            self.assertTrue(evaluate(stored, rule))
            alert = create_alert(stored, rule, "2026-09-03T12:01:00Z")
            self.assertEqual((1, 0), insert_alerts(connection, [alert]))
            self.assertEqual((0, 1), insert_alerts(connection, [alert]))
            trace = trace_alert(connection, alert.alert_id)
            raw_xml = connection.execute("SELECT raw_xml FROM events WHERE id = ?", (trace["event_id"],)).fetchone()[0]
            connection.close()
        self.assertEqual("DET-001", trace["detection_id"])
        self.assertEqual("T1059.001", trace["rule_technique_id"])
        self.assertEqual("Execution/example.evtx", trace["source_file"])
        self.assertEqual("T1086", trace["upstream_techniques"][0]["id"])
        self.assertEqual("<Event>preserved evidence</Event>", raw_xml)


if __name__ == "__main__":
    unittest.main()
