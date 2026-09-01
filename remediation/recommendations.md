# Remediation and Control Recommendations

## Contain and preserve — first hours

| Priority | Action | Owner | Completion evidence |
|---|---|---|---|
| P0 | Isolate `FIN-WS01` through EDR without powering it off | SOC / Endpoint | Isolation status and timestamp |
| P0 | Revoke sessions; reset credentials and verify MFA out-of-band | IAM | Identity audit record and user verification |
| P0 | Preserve endpoint, identity, VPN, email, network, and app logs | IR | Hashes, collection log, evidence location |
| P1 | Block validated indicators only after checking shared/VPN infrastructure | SOC / Network | Change ticket and scoped rule |
| P1 | Hunt identity, source, process tree, and command enterprise-wide | Threat Detection | Queries and results |

## Eradicate and recover

1. Forensically examine or reimage according to policy; do not rely on an antivirus scan alone.
2. Rotate exposed secrets based on evidence, including tokens in the affected user context.
3. Patch the endpoint and Office; remove any validated persistence.
4. Restore required finance data from known-good sources and have the process owner validate integrity.
5. Monitor the identity and rebuilt device, then require SOC and business-owner closure approval.

## Control improvements

| Control | Rationale | Measure |
|---|---|---|
| Phishing-resistant MFA and conditional access | Reduces stolen-password utility | Coverage and blocked risky sign-ins |
| Privileged separation and just-in-time elevation | Limits blast radius | Standing privileges and JIT adoption |
| Constrained PowerShell/application control where feasible | Limits unapproved scripts | Coverage and exception age |
| Script-block/module logging plus Sysmon | Improves visibility | Coverage and ingestion latency |
| Office child-process prevention/detection | Interrupts suspicious ancestry | Coverage and false-positive rate |
| Enriched failure-to-success correlation | Finds misuse sooner | Precision and mean time to triage |
| Tested playbooks and evidence retention | Improves response consistency | Exercise findings closure |

## NIST CSF 2.0 application

CSF 2.0 has six concurrent Functions, including cross-cutting **Govern**.

| Function | Applied outcome |
|---|---|
| Govern | Define risk tolerance, roles, escalation, retention, and financial/regulatory decision owners |
| Identify | Inventory the endpoint, identity, finance data, dependencies, and business impact |
| Protect | Apply MFA, least privilege, hardening, application control, secure configuration, and awareness |
| Detect | Centralize Windows/Sysmon/PowerShell/IAM telemetry and correlate authentication with process ancestry |
| Respond | Triage, preserve, contain, communicate, scope, and eradicate |
| Recover | Rebuild known-good, validate data/process integrity, monitor, and learn |

Validate through a safe purple-team simulation with inert commands and a test identity/host. Confirm telemetry, timestamps, fields, ingestion, correlation, ticketing, and routing; tune narrow documented exceptions rather than disabling logs.
