import unittest

from ioc.extractor import extract_values


class ExtractorTests(unittest.TestCase):
    def test_extracts_supported_observable_types(self):
        event = {
            "hostname": "FIN-WS01", "username": r"WESTBRIDGE\jsmith",
            "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_process": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
            "command_line": "powershell.exe -File C:\\Temp\\audit.ps1 https://updates.example.test/payload",
            "source_ip": "192.0.2.15",
            "event_data": {"Hashes": "SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        }
        values = extract_values(event)
        by_type = {}
        for ioc_type, value, source in values:
            by_type.setdefault(ioc_type, []).append(value)
        self.assertIn("192.0.2.15", by_type["ip"])
        self.assertIn("FIN-WS01", by_type["hostname"])
        self.assertIn(r"WESTBRIDGE\jsmith", by_type["username"])
        self.assertIn("powershell.exe", [item.casefold() for item in by_type["process"]])
        self.assertIn("sha256:" + "a" * 64, by_type["hash"])
        self.assertIn("updates.example.test", by_type["domain"])
        self.assertIn(event["command_line"], by_type["command_line"])
        self.assertIn(event["process_name"], by_type["file_path"])

    def test_event_without_observables_returns_empty(self):
        self.assertEqual([], extract_values({"event_data": {}}))

    def test_deduplicates_same_process_within_event(self):
        path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        values = extract_values({"process_name": path, "event_data": {"Image": path}})
        processes = [item for item in values if item[0] == "process"]
        self.assertEqual(1, len(processes))

    def test_does_not_treat_powershell_method_names_as_domains(self):
        command = "$Host.ui.PromptForCredential(); $cred.GetNetworkCredential()"
        domains = [item for item in extract_values({"command_line": command, "event_data": {}}) if item[0] == "domain"]
        self.assertEqual([], domains)


if __name__ == "__main__":
    unittest.main()
