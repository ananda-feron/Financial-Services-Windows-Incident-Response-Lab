import tempfile
import unittest
from pathlib import Path

from dashboard.app import create_app
from detection_engine.database import insert_alerts
from detection_engine.engine import create_alert, database_events
from detection_engine.loader import load_rule
from incidents.database import persist_incidents
from incidents.engine import correlate, load_alerts
from ingestion.database import connect, insert_events

ROOT = Path(__file__).parents[2]


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(); self.db = Path(self.directory.name) / "events.db"
        connection = connect(self.db)
        event = {"timestamp":"2026-09-03T13:00:00Z","event_id":10,"event_record_id":"1","record_index":1,
          "computer":"FIN-WS01","username":r"WESTBRIDGE\jsmith","process_name":None,"parent_process":None,
          "command_line":None,"source_ip":None,"source":"Sysmon","provider":"Microsoft-Windows-Sysmon",
          "dataset":"EVTX-ATTACK-SAMPLES","source_file":"Credential Access/babyshark_mimikatz_powershell.evtx",
          "source_category":"Credential Access","attack_technique":"T1003.001","attack_technique_name":"LSASS Memory",
          "attack_tactic":"Credential Access","curated_technique_id":"T1003.001","curated_technique_name":"LSASS Memory",
          "curated_by":"analyst","curated_at":"2026-09-03","mapping_rationale":"test","upstream_techniques":[],
          "event_data":{"TargetImage":r"C:\Windows\System32\lsass.exe","SourceImage":r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","GrantedAccess":"0x00001010"},"raw_xml":"<Event>lsass</Event>"}
        insert_events(connection,[event]); stored=database_events(connection)[0]
        rule=load_rule(ROOT/"detection_engine/rules/det-003-lsass-process-access.yaml")
        alert=create_alert(stored,rule,"2026-09-03T13:01:00Z"); insert_alerts(connection,[alert])
        incident=correlate(load_alerts(connection),recorded_at="2026-09-03T13:02:00Z")[0]
        persist_incidents(connection,[incident]); connection.close(); self.incident_id=incident.incident_id
        self.app=create_app(self.db); self.app.config["TESTING"]=True; self.client=self.app.test_client()

    def tearDown(self): self.directory.cleanup()

    def test_four_primary_views_render_live_data(self):
        for path in ("/", "/detections", "/incidents", "/attack"):
            self.assertEqual(200, self.client.get(path).status_code)
        self.assertIn(b"FIN-WS01", self.client.get("/incidents").data)

    def test_incident_filter_and_global_search(self):
        self.assertIn(self.incident_id.encode(), self.client.get("/incidents?severity=critical").data)
        self.assertNotIn(self.incident_id.encode(), self.client.get("/incidents?severity=low").data)
        self.assertIn(b"FIN-WS01", self.client.get("/search?q=FIN-WS01").data)

    def test_evidence_drilldown_records_audit_event(self):
        page=self.client.get(f"/incidents/{self.incident_id}"); self.assertIn(b"View referenced original XML",page.data)
        raw=self.client.get("/evidence/1"); self.assertEqual("application/xml; charset=utf-8",raw.content_type)
        connection=connect(self.db); actions={r[0] for r in connection.execute("SELECT action FROM audit_log")}; connection.close()
        self.assertEqual({"VIEW_INCIDENT","VIEW_EVIDENCE"},actions)

    def test_rbac_blocks_viewer_and_allows_analyst_note(self):
        blocked=self.client.post(f"/incidents/{self.incident_id}/notes",data={"body":"reviewed"})
        self.assertEqual(403,blocked.status_code)
        allowed=self.client.post(f"/incidents/{self.incident_id}/notes?role=ANALYST",data={"body":"Evidence reviewed."})
        self.assertEqual(302,allowed.status_code)
        connection=connect(self.db); self.assertEqual(1,connection.execute("SELECT COUNT(*) FROM notes").fetchone()[0]); connection.close()


if __name__ == "__main__": unittest.main()
