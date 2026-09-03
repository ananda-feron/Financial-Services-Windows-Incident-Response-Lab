import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ingestion.database import connect, insert_events
from ingestion.metadata import enrich
from ingestion.normalize import normalize_event

EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>
<EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-08-01T12:00:00.000000Z"/>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>FIN-WS01</Computer></System>
<EventData><Data Name="User">WESTBRIDGE\\jsmith</Data>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\WINWORD.EXE</Data>
<Data Name="CommandLine">powershell.exe Get-Process</Data></EventData></Event>"""

METADATA = {
    "dataset": "EVTX-ATTACK-SAMPLES", "source_file": "Execution/example.evtx",
    "source_category": "Execution", "technique_id": "T1059.001",
    "technique_name": "PowerShell", "attack_tactic": "Execution",
    "upstream_techniques": [],
}


class NormalizeTests(unittest.TestCase):
    def test_normalizes_system_and_event_data(self):
        event = normalize_event(EVENT_XML, METADATA, 1)
        self.assertEqual(1, event["event_id"])
        self.assertEqual("FIN-WS01", event["computer"])
        self.assertTrue(event["process_name"].endswith("powershell.exe"))
        self.assertEqual("T1059.001", event["attack_technique"])
        self.assertEqual("WESTBRIDGE\\jsmith", event["username"])

    def test_rejects_event_without_system(self):
        with self.assertRaisesRegex(ValueError, "System"):
            normalize_event("<Event><EventData/></Event>", METADATA, 1)


class MetadataTests(unittest.TestCase):
    def test_preserves_curated_and_upstream_mappings(self):
        sample = dict(METADATA)
        upstream = {"example.evtx": {"tactics": ["Execution"], "techniques": [{"id": "T1086", "name": "PowerShell"}]}}
        result = enrich(sample, upstream)
        self.assertEqual("T1059.001", result["technique_id"])
        self.assertEqual("T1086", result["upstream_techniques"][0]["id"])


class DatabaseTests(unittest.TestCase):
    def test_insert_is_idempotent_and_keeps_raw_xml(self):
        event = normalize_event(EVENT_XML, METADATA, 1)
        with tempfile.TemporaryDirectory() as directory:
            connection = connect(Path(directory) / "events.db")
            self.assertEqual((1, 0), insert_events(connection, [event]))
            self.assertEqual((0, 1), insert_events(connection, [event]))
            row = connection.execute("SELECT raw_xml, technique_id FROM events").fetchone()
            connection.close()
        self.assertEqual(EVENT_XML, row[0])
        self.assertEqual("T1059.001", row[1])


if __name__ == "__main__":
    unittest.main()
