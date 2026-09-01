import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "detection" / "event_parser.py"
SPEC = importlib.util.spec_from_file_location("event_parser", MODULE_PATH)
event_parser = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = event_parser
SPEC.loader.exec_module(event_parser)


class EventParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = Path(__file__).parents[1] / "evidence" / "sample-events.jsonl"
        cls.events = event_parser.load_events(fixture)
        cls.findings = event_parser.analyze(cls.events)

    def test_correlates_attack_chain(self):
        rules = {item.rule for item in self.findings}
        expected = {"AUTH_FAILURE_BURST", "AUTH_SUCCESS_AFTER_FAILURES", "PRIVILEGED_LOGON_CHAIN", "POWERSHELL_PROCESS", "DISCOVERY_COMMAND"}
        self.assertTrue(expected.issubset(rules))

    def test_expected_risk_is_high(self):
        self.assertEqual("High", event_parser.risk(self.findings))

    def test_benign_powershell_is_low_severity(self):
        items = [item for item in self.findings if item.rule == "POWERSHELL_PROCESS"]
        self.assertEqual(["low", "high"], [item.severity for item in items])

    def test_requires_timezone(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            event_parser.parse_timestamp("2025-03-14T13:42:02")


if __name__ == "__main__":
    unittest.main()
