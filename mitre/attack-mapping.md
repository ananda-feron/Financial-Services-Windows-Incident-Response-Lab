# MITRE ATT&CK Mapping

Mappings describe observed behavior, not actor attribution. Failed logons themselves are not Valid Accounts; the successful use after failures is the relevant observation.

| Observation | Technique | Evidence | Confidence | Caveat |
|---|---|---|---|---|
| Type-10 success after five failures from same source | [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Security 4624/4625 correlation | Moderate | Confirm source was not authorized VPN/support infrastructure |
| PowerShell launched by Word with policy bypass | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | Sysmon image, parent, command line | High | PowerShell is dual-use; context makes this suspicious |
| `Get-LocalUser` and `whoami /all` | [T1087 — Account Discovery](https://attack.mitre.org/techniques/T1087/) | Command line and child process | High | `whoami` also provides privilege/context detail |
| `Get-Process` | [T1057 — Process Discovery](https://attack.mitre.org/techniques/T1057/) | PowerShell command line | High | Intent is not established |

## Detection opportunities

- Correlate 4625 bursts with 4624 by user, source, host, logon type, and time window.
- Alert on Office spawning PowerShell, script hosts, `mshta`, or shells; tune approved automation.
- Capture Sysmon process creation and PowerShell script-block logging, then centralize/protect logs.
- Join endpoint alerts with IAM, VPN, device-compliance, geo-velocity, and MFA data.
- Baseline 4672 by identity and logon type; never alert on it in isolation.

ATT&CK explains behavior; it does not prove intent, actor, or impact. This dataset does not support persistence, credential dumping, lateral movement, collection, or exfiltration mappings.
