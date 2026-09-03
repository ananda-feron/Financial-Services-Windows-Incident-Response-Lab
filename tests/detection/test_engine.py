import unittest
from pathlib import Path

from detection_engine.engine import create_alert, evaluate
from detection_engine.loader import load_rule, load_rules

ROOT = Path(__file__).parents[2]
RULES = ROOT / "detection_engine" / "rules"


def event(**changes):
    base = {
        "id": 42, "event_key": "event-key-42", "event_id": 1,
        "process_name": None, "parent_process": None, "command_line": None,
        "provider": "Microsoft-Windows-Sysmon", "event_data": {},
        "source_file": "Execution/example.evtx", "dataset": "EVTX-ATTACK-SAMPLES",
        "curated_technique_id": "T1059.001", "curated_technique_name": "PowerShell",
        "curated_by": "Project analyst", "curated_at": "2026-09-03",
        "mapping_rationale": "Test mapping", "upstream_techniques": [],
    }
    base.update(changes)
    return base


class RuleLoaderTests(unittest.TestCase):
    def test_loads_three_versioned_rules(self):
        rules = load_rules(RULES)
        self.assertEqual(["DET-001", "DET-002", "DET-003"], [rule.id for rule in rules])
        self.assertTrue(all(rule.version == "1.0" for rule in rules))


class EvaluatorTests(unittest.TestCase):
    def test_suspicious_powershell_positive_and_benign_negative(self):
        rule = load_rule(RULES / "det-001-suspicious-powershell.yaml")
        positive = event(process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", command_line="powershell.exe -NoP Get-Process")
        negative = event(process_name=r"C:\Program Files\Google\Chrome\chrome.exe", command_line="chrome.exe")
        self.assertTrue(evaluate(positive, rule))
        self.assertFalse(evaluate(negative, rule))

    def test_wmi_process_positive_and_normal_parent_negative(self):
        rule = load_rule(RULES / "det-002-wmi-process-creation.yaml")
        positive = event(process_name=r"C:\Windows\System32\cmd.exe", parent_process=r"C:\Windows\System32\wbem\WmiPrvSE.exe")
        negative = event(process_name=r"C:\Windows\System32\cmd.exe", parent_process=r"C:\Windows\explorer.exe")
        self.assertTrue(evaluate(positive, rule))
        self.assertFalse(evaluate(negative, rule))

    def test_lsass_access_positive_and_non_lsass_negative(self):
        rule = load_rule(RULES / "det-003-lsass-process-access.yaml")
        values = {"TargetImage": r"C:\Windows\System32\lsass.exe", "SourceImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "GrantedAccess": "0x00001010"}
        positive = event(event_id=10, event_data=values)
        negative = event(event_id=10, event_data={**values, "TargetImage": r"C:\Windows\System32\notepad.exe"})
        self.assertTrue(evaluate(positive, rule))
        self.assertFalse(evaluate(negative, rule))

    def test_alert_identity_is_deterministic_and_versioned(self):
        rule = load_rule(RULES / "det-001-suspicious-powershell.yaml")
        first = create_alert(event(), rule, "2026-09-03T12:00:00Z")
        second = create_alert(event(), rule, "2026-09-03T12:01:00Z")
        self.assertEqual(first.alert_id, second.alert_id)
        self.assertEqual("1.0", first.rule_version)
        self.assertEqual("T1059.001", first.technique_id)


if __name__ == "__main__":
    unittest.main()
