import sqlite3
import tempfile
import unittest
from pathlib import Path

from detection_engine.database import insert_alerts
from detection_engine.engine import create_alert, database_events, evaluate
from detection_engine.loader import load_rule
from incidents.database import add_note, evidence_xml, notes, persist_incidents, timeline
from incidents.engine import correlate, load_alerts
from incidents.view import render_incident_page
from ingestion.database import connect, insert_events

ROOT = Path(__file__).parents[2]


def normalized(record, timestamp, event_id, process, command, event_data, technique):
    return {
        "timestamp": timestamp, "event_id": event_id, "event_record_id": str(record),
        "record_index": record, "computer": "FIN-WS01", "username": r"WESTBRIDGE\jsmith",
        "process_name": process, "parent_process": r"C:\Windows\explorer.exe",
        "command_line": command, "source_ip": None,
        "source": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon",
        "dataset": "EVTX-ATTACK-SAMPLES", "source_file": "Credential Access/golden.evtx",
        "source_category": "Credential Access", "attack_technique": technique,
        "attack_technique_name": technique, "attack_tactic": "Credential Access",
        "curated_technique_id": technique, "curated_technique_name": technique,
        "curated_by": "Project analyst", "curated_at": "2026-09-03",
        "mapping_rationale": "Golden-path mapping", "upstream_techniques": [],
        "event_data": event_data, "raw_xml": f"<Event><Record>{record}</Record></Event>",
    }


class IncidentGoldenPathTests(unittest.TestCase):
    def test_normalized_events_to_correlated_investigation_and_evidence(self):
        powershell = normalized(
            1, "2026-09-03T13:00:00Z", 1,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoP Get-Process", {}, "T1059.001")
        lsass_data = {"TargetImage": r"C:\Windows\System32\lsass.exe",
                      "SourceImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      "GrantedAccess": "0x00001010"}
        lsass = normalized(2, "2026-09-03T13:02:00Z", 10, None, None, lsass_data, "T1003.001")
        with tempfile.TemporaryDirectory() as directory:
            connection = connect(Path(directory) / "events.db")
            self.assertEqual((2, 0), insert_events(connection, [powershell, lsass]))
            stored = database_events(connection)
            ps_rule = load_rule(ROOT / "detection_engine/rules/det-001-suspicious-powershell.yaml")
            lsass_rule = load_rule(ROOT / "detection_engine/rules/det-003-lsass-process-access.yaml")
            alerts = [create_alert(stored[0], ps_rule, "2026-09-03T13:05:00Z"),
                      create_alert(stored[1], lsass_rule, "2026-09-03T13:05:01Z")]
            self.assertTrue(evaluate(stored[0], ps_rule))
            self.assertTrue(evaluate(stored[1], lsass_rule))
            self.assertEqual((2, 0), insert_alerts(connection, alerts))
            incidents = correlate(load_alerts(connection), recorded_at="2026-09-03T13:06:00Z")
            self.assertEqual(1, len(incidents))
            self.assertEqual((1, 2, 2), persist_incidents(connection, incidents))
            incident_id = incidents[0].incident_id
            add_note(connection, incident_id, "Project analyst", "PowerShell preceded LSASS access.", "2026-09-03T13:07:00Z")
            entries = timeline(connection, incident_id)
            raw = evidence_xml(connection, incident_id, entries[0].event_id)
            saved_notes = notes(connection, incident_id)
            page = Path(directory) / "incident.html"
            render_incident_page(connection, incident_id, page)
            page_text = page.read_text(encoding="utf-8")
            counts = tuple(connection.execute("SELECT (SELECT COUNT(*) FROM incident_alerts), (SELECT COUNT(*) FROM incident_evidence)").fetchone())
            connection.close()
        self.assertEqual(["T1059.001", "T1003.001"], [entry.technique_id for entry in entries])
        self.assertEqual((2, 2), counts)
        self.assertEqual("<Event><Record>1</Record></Event>", raw)
        self.assertEqual("PowerShell preceded LSASS access.", saved_notes[0].body)
        self.assertIn(incident_id, page_text)
        self.assertIn("View referenced original event XML", page_text)
        self.assertIn("PowerShell preceded LSASS access.", page_text)


if __name__ == "__main__":
    unittest.main()
