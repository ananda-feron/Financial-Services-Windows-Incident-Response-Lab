# Investigation Timeline

Times are UTC on 14 March 2025. `198.51.100.24` is an IANA documentation address used only for simulation.

| Time | Source / Event | Observation | Interpretation |
|---|---|---|---|
| 13:30:00 | Security 4624 | Normal console logon by `jsmith` from `10.20.30.41` | Baseline activity |
| 13:35:12 | Sysmon 1 | `explorer.exe` starts PowerShell with `Get-Date` | Benign comparison; PowerShell alone is insufficient |
| 13:42:02–13:44:15 | Security 4625 | Five type-10 failures from `198.51.100.24` | Suspicious due to source, cadence, and later success |
| 13:45:01 | Security 4624 | Type-10 success for same user/source | Strong correlation to failure burst |
| 13:45:03 | Security 4672 | Sensitive privileges assigned | Validate actual privileges and baseline |
| 13:47:22 | Sysmon 1 | Word starts PowerShell with `-NoP`, bypass, `Get-LocalUser`, `Get-Process` | Suspicious Office-to-PowerShell execution and discovery |
| 13:48:09 | Sysmon 1 | PowerShell starts `whoami.exe /all` | Additional identity/privilege discovery |

## Missing evidence and next queries

- Match logon IDs across original 4624, 4672, and process events.
- Determine whether the source represents fictional VPN/NAT infrastructure.
- Review 4688, PowerShell 4103/4104, Sysmon network/file/registry, EDR, Prefetch, and Amcache.
- Validate user schedule, remote-work pattern, and support/change records.
- Search mail telemetry for the document preceding Word execution.
- Review finance application/file audit logs before making any data-impact claim.

## Chain of custody

In a real incident, export original artifacts read-only, record collector identity and UTC time, calculate SHA-256 hashes, preserve originals in restricted storage, and analyze verified copies. The lab JSONL is normalized synthetic evidence, not a forensic original.
