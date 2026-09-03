import tempfile
import unittest
from pathlib import Path

from detection_engine.database import insert_alerts
from detection_engine.engine import create_alert, database_events, evaluate
from detection_engine.loader import load_rule
from incidents.database import persist_incidents
from incidents.engine import correlate, load_alerts
from ingestion.database import connect, insert_events
from ioc.database import persist_observations, trace_ioc
from ioc.extractor import extract_incident

ROOT = Path(__file__).parents[2]


class IOCGoldenPathTests(unittest.TestCase):
    def test_incident_event_to_deduplicated_ioc_and_original_xml(self):
        normalized = {
            "timestamp": "2026-09-03T13:00:00Z", "event_id": 1,
            "event_record_id": "42", "record_index": 1, "computer": "FIN-WS01",
            "username": r"WESTBRIDGE\jsmith",
            "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_process": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
            "command_line": "powershell.exe -NoP https://updates.example.test/payload",
            "source_ip": "192.0.2.15", "source": "Microsoft-Windows-Sysmon/Operational",
            "provider": "Microsoft-Windows-Sysmon", "dataset": "EVTX-ATTACK-SAMPLES",
            "source_file": "Execution/golden.evtx", "source_category": "Execution",
            "attack_technique": "T1059.001", "attack_technique_name": "PowerShell",
            "attack_tactic": "Execution", "curated_technique_id": "T1059.001",
            "curated_technique_name": "PowerShell", "curated_by": "Project analyst",
            "curated_at": "2026-09-03", "mapping_rationale": "Golden mapping",
            "upstream_techniques": [],
            "event_data": {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
            "raw_xml": "<Event><SourceIp>192.0.2.15</SourceIp></Event>",
        }
        with tempfile.TemporaryDirectory() as directory:
            connection = connect(Path(directory) / "events.db")
            insert_events(connection, [normalized])
            stored = database_events(connection)[0]
            rule = load_rule(ROOT / "detection_engine/rules/det-001-suspicious-powershell.yaml")
            self.assertTrue(evaluate(stored, rule))
            insert_alerts(connection, [create_alert(stored, rule, "2026-09-03T13:01:00Z")])
            incident = correlate(load_alerts(connection), recorded_at="2026-09-03T13:02:00Z")[0]
            persist_incidents(connection, [incident])
            observations = extract_incident(connection, incident.incident_id)
            first = persist_observations(connection, observations)
            second = persist_observations(connection, observations)
            self.assertEqual(len(observations), first[0])
            self.assertEqual((0, len(observations), 0), second)
            ioc_id = connection.execute("SELECT ioc_id FROM iocs WHERE type='ip' AND value='192.0.2.15'").fetchone()[0]
            traced = trace_ioc(connection, ioc_id)
            connection.close()
        self.assertEqual(incident.incident_id, traced["incident_id"])
        self.assertEqual("Execution/golden.evtx", traced["source_file"])
        self.assertEqual("EVTX-ATTACK-SAMPLES", traced["dataset"])
        self.assertIn("192.0.2.15", traced["raw_xml"])


if __name__ == "__main__":
    unittest.main()
