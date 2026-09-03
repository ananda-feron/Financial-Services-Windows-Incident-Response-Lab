import unittest
from datetime import datetime, timedelta, timezone

from incidents.engine import correlate
from incidents.models import CorrelationAlert, highest_severity


def alert(number, timestamp, hostname="FIN-WS01", username=r"WESTBRIDGE\jsmith",
          technique="T1059.001", tactic="Execution", severity="high"):
    return CorrelationAlert(
        database_alert_id=number, alert_id=f"ALERT-{number:03d}", detection_id="DET-001",
        severity=severity, technique_id=technique, technique_name=technique,
        tactic=tactic, event_id=number, event_key=f"key-{number}",
        timestamp=timestamp, hostname=hostname, username=username,
        source_file=f"Execution/sample-{number}.evtx", dataset="EVTX-ATTACK-SAMPLES",
    )


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 9, 3, 13, 0, tzinfo=timezone.utc)
        self.recorded = "2026-09-03T14:00:00Z"

    def test_same_host_user_window_and_related_activity_correlates(self):
        alerts = [
            alert(1, self.start, technique="T1059.001", tactic="Execution", severity="high"),
            alert(2, self.start + timedelta(minutes=2), technique="T1003.001", tactic="Credential Access", severity="critical"),
        ]
        incidents = correlate(alerts, recorded_at=self.recorded)
        self.assertEqual(1, len(incidents))
        self.assertEqual(2, len(incidents[0].alerts))
        self.assertEqual("critical", incidents[0].severity)

    def test_same_host_far_apart_creates_separate_incidents(self):
        alerts = [alert(1, self.start), alert(2, self.start + timedelta(hours=1))]
        self.assertEqual(2, len(correlate(alerts, recorded_at=self.recorded)))

    def test_different_hosts_do_not_correlate(self):
        alerts = [alert(1, self.start, hostname="FIN-WS01"), alert(2, self.start, hostname="FIN-WS99")]
        self.assertEqual(2, len(correlate(alerts, recorded_at=self.recorded)))

    def test_different_named_users_do_not_correlate(self):
        alerts = [alert(1, self.start, username="alice"), alert(2, self.start, username="bob")]
        self.assertEqual(2, len(correlate(alerts, recorded_at=self.recorded)))

    def test_current_four_alert_shape_becomes_three_incidents(self):
        alerts = [
            alert(1, datetime(2019, 4, 18, 16, 58, 14, tzinfo=timezone.utc), username=None, technique="T1003.001", tactic="Credential Access", severity="critical"),
            alert(2, datetime(2019, 4, 18, 17, 1, 35, tzinfo=timezone.utc), username=None, technique="T1003.001", tactic="Credential Access", severity="critical"),
            alert(3, datetime(2019, 5, 11, 17, 58, 50, tzinfo=timezone.utc), username=r"NT AUTHORITY\SYSTEM", technique="T1047", tactic="Execution"),
            alert(4, datetime(2019, 9, 9, 13, 35, 9, tzinfo=timezone.utc), hostname="MSEDGEWIN10", username=None, technique="T1059.001", tactic="Execution"),
        ]
        incidents = correlate(alerts, recorded_at=self.recorded)
        self.assertEqual([2, 1, 1], [len(item.alerts) for item in incidents])

    def test_severity_aggregation_is_explicit_maximum(self):
        self.assertEqual("critical", highest_severity(["low", "high", "critical", "medium"]))


if __name__ == "__main__":
    unittest.main()
