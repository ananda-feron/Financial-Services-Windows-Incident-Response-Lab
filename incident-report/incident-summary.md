# Incident Summary — WBF-IR-2025-001

## Disposition

**Suspected account and endpoint compromise — containment required.**

On 14 March 2025, the service desk opened ticket `SD-2025-0314-117` after Finance/Risk employee Jordan Smith reported Word freezing and a brief PowerShell window on `FIN-WS01`. Synthetic Windows and Sysmon telemetry shows five failed RemoteInteractive logons from `198.51.100.24`, a successful logon from the same source 46 seconds later, special privileges, and PowerShell spawned by `WINWORD.EXE`.

The PowerShell command used execution-policy bypass and performed local-account and process discovery. This sequence is inconsistent with the user's normal activity and meets the lab's correlation rules.

## Scope and assessment

- Asset: `FIN-WS01`; identity: `WESTBRIDGE\jsmith`; owner: Finance/Risk
- Detection interval: 13:42:02–13:47:22 UTC
- Sources: synthetic Security 4624/4625/4672 and Sysmon process-create events
- Severity: **High**; confidence: **Moderate**

The workstation supports financial forecasting and risk reporting. Unauthorized access could affect sensitive information and decision-support data. The dataset does **not** confirm file access, transaction changes, persistence, command-and-control, or exfiltration.

## Immediate actions

1. Isolate `FIN-WS01` while retaining power and volatile evidence.
2. Revoke sessions and reset `jsmith` credentials through a verified channel; review MFA methods.
3. Preserve Security, Sysmon, PowerShell, EDR, VPN, Entra/AD, DNS, proxy, email, and application telemetry.
4. Hunt for the source, process chain, command, and identity activity across the environment.
5. Escalate to IR, IAM, Finance/Risk, and Legal/Privacy according to validated scope.

## Analyst judgment

The leading hypothesis is misuse of a valid account followed by execution in the user's context. Authorized support plus legitimate Office automation is less likely but must be checked against VPN ownership, change/support records, and user confirmation. Event 4672 is contextual evidence, not proof of privilege escalation.
