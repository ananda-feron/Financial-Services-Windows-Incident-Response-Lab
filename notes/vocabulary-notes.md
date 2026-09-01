# Vocabulary Notes

These notes explain how terminology applies to this investigation. The goal is to show analytical understanding—not simply memorize definitions.

## Identity and authentication

| Term | Meaning | Application in this lab | Important distinction |
|---|---|---|---|
| Authentication | Verifying that a user or system is who it claims to be | Windows records attempted and successful logons for `jsmith` | Authentication answers “who are you?”; authorization answers “what may you do?” |
| Authorization | Determining which resources/actions an authenticated identity may access | Assigned privileges affect the possible impact of the session | A successful logon does not automatically mean broad access |
| IAM | Policies, processes, and technology managing identity lifecycles and access | Credential reset, session revocation, MFA review, and privilege validation are IAM actions | IAM includes governance and lifecycle controls, not just account creation |
| Valid account | A legitimate account used by its owner or misused by another party | The success after failures supports ATT&CK T1078 as a hypothesis | “Valid” describes the credential/account, not whether the activity is authorized |
| MFA | Two or more factors from knowledge, possession, or inherence categories | Responders review `jsmith` MFA methods after suspected credential misuse | Two passwords are not two factors; MFA can still be phished or fatigue-abused |
| Logon Type 10 | Windows RemoteInteractive logon, commonly associated with RDP/Terminal Services | The suspicious failures and success use type 10 | It describes the session type, not whether the login was malicious |
| Event 4625 | Windows audit event for a failed logon | Five events form the failure burst | One failure is common noise; status, source, cadence, and later activity create context |
| Event 4624 | Windows audit event for a successful logon | Same user/source succeeds 46 seconds after the last failure | A 4624 is not proof that the human account owner initiated it |
| Event 4672 | Sensitive privileges assigned to a new logon | Adds possible-impact context after the correlated success | It is not proof that privilege escalation occurred; privileged/service logons often generate it |

## Endpoint and process telemetry

| Term | Meaning | Application in this lab | Important distinction |
|---|---|---|---|
| Endpoint | A user or server device connected to an organization’s environment | `FIN-WS01` is the investigated finance endpoint | Endpoint protection and endpoint detection/response are related but different control capabilities |
| Sysmon | Microsoft Sysinternals service/driver that adds detailed Windows telemetry when configured | Sysmon Event 1 supplies image, parent, user, and command line | Sysmon collects telemetry; it is not a SIEM and does not automatically decide intent |
| Process creation | The operating system starting a program as a new process | Word starts PowerShell, then PowerShell starts `whoami.exe` | Process creation proves execution occurred, not why it occurred |
| Parent process | The process recorded as creating another process | `WINWORD.EXE` is PowerShell’s parent | Parent-child relationships can be spoofed or affected by implementation details; corroborate with EDR |
| Command line | Arguments supplied when a process starts | `-NoP`, policy bypass, and discovery commands raise suspicion | Suspicious strings are indicators, not conclusive proof of maliciousness |
| PowerShell | Windows automation and scripting environment | Used for account and process discovery | PowerShell is dual-use; context and behavior matter more than its mere presence |
| Execution-policy bypass | Starting PowerShell in a way that avoids its script execution-policy restriction | Appears in the synthetic suspicious command | Execution policy is a safety feature, not a strong security boundary |
| Living off the land | Abusing legitimate built-in tools for malicious objectives | PowerShell and `whoami` can be used without dropping a custom tool | Use of a native utility alone does not establish malicious intent |

## Detection and investigation

| Term | Meaning | Application in this lab | Important distinction |
|---|---|---|---|
| Indicator | An observable associated with potentially unwanted activity | Source IP, command arguments, and process ancestry are indicators | An indicator is not necessarily an indicator of compromise until validated in context |
| Correlation | Linking separate events using common entities and time relationships | Same host, user, source, and time connect failures to success and execution | Correlation supports a hypothesis; it does not prove causation |
| Detection rule | Logic that selects behavior worth review | Three failures within ten minutes and a success within fifteen minutes | A rule produces findings/alerts, not final incident conclusions |
| Threshold | A numerical condition used by a rule | Three failures trigger the lab burst finding | Thresholds require baselining and tuning; lower is more sensitive but usually noisier |
| False positive | Benign activity incorrectly treated as malicious | Approved remote support could resemble part of this chain | A false positive is not a broken alert if the alert correctly requested human validation |
| False negative | Malicious activity missed by a control or rule | An attacker using another interpreter could avoid the PowerShell rule | Improving coverage often increases data volume and false positives |
| Triage | Initial validation, prioritization, and routing of an alert/report | Service desk signal and telemetry are combined before escalation | Triage is narrower than a complete forensic investigation |
| Timeline | Ordered reconstruction of relevant activity | The report sequences events from 13:42–13:48 UTC | Clock skew, time zones, ingestion time, and event time must be distinguished |
| Scope | Identities, systems, data, and time range affected or requiring review | Confirmed scope is one endpoint/account; enterprise hunting tests wider exposure | Absence from the small dataset is not evidence that broader activity did not occur |
| Hypothesis | A testable explanation for observed evidence | Leading hypothesis: valid-account misuse followed by user-context execution | Analysts should retain and test alternate explanations |
| Confidence | Strength of support for an analytical judgment | Moderate due to consistent events but missing network/identity/email evidence | Confidence and severity are separate: uncertainty can coexist with high potential impact |

## Incident response and evidence

| Term | Meaning | Application in this lab | Important distinction |
|---|---|---|---|
| Containment | Limiting ongoing damage or spread | Isolate `FIN-WS01`, revoke sessions, and secure the identity | Containment is not eradication; the root cause may remain |
| Eradication | Removing attacker access, malicious artifacts, and root cause | Reimage as required and rotate exposed secrets | Rebuilding a host without securing the identity can leave access intact |
| Recovery | Restoring validated operations and monitoring for recurrence | Return a known-good device after data/process-owner validation | Recovery should not begin solely because an antivirus scan is clean |
| Chain of custody | Documented control and transfer history for evidence | Record collector, UTC time, hashes, storage, and analysis copy | A hash supports integrity; it does not prove how the original evidence was acquired |
| Forensic image | Bit-for-bit acquisition of a storage medium or defined evidence source | Listed as a possible deeper collection step | Copying selected files is not the same as a full forensic image |
| Volatile evidence | Data likely lost when a system powers down, such as memory and active connections | Keep the isolated endpoint powered when policy and responders permit | Preservation priorities depend on safety, legal authority, and IR procedures |

## Risk, governance, and frameworks

| Term | Meaning | Application in this lab | Important distinction |
|---|---|---|---|
| Threat | A circumstance or actor capable of causing harm | Possible credential misuse and unauthorized execution | A threat is not the same as a vulnerability or realized impact |
| Vulnerability | A weakness that can be exploited | Weak authentication or insufficient endpoint controls might be investigated | The events do not by themselves prove which vulnerability enabled the activity |
| Likelihood | Assessed chance that the risk scenario occurs or is occurring | Rated Medium because evidence is suggestive but incomplete | Likelihood is not confidence; one estimates risk, the other supports an analytical judgment |
| Impact | Consequence if the scenario occurs | High because the endpoint supports sensitive Finance/Risk work | Asset sensitivity raises potential impact but does not prove data was affected |
| Inherent risk | Risk before considering relevant controls | Account/endpoint compromise could have high business consequence | It should not be confused with the risk remaining after controls operate |
| Residual risk | Risk remaining after controls and treatment | Target is Medium after MFA, hardening, visibility, and response improvements | Residual risk rarely becomes zero |
| Compensating control | Alternative control that meets an objective when the preferred control is unavailable | Strong monitoring might partially compensate while prevention is improved | Compensation must be designed, operated, and evidenced—not merely claimed |
| SOX deficiency | A control deficiency relevant to internal control over financial reporting, classified through formal evaluation | Control owners assess whether financial-reporting controls failed | A cyber incident is not automatically a SOX deficiency or material weakness |
| MITRE ATT&CK | Knowledge base describing adversary tactics and techniques | Maps PowerShell, Valid Accounts, Account Discovery, and Process Discovery | ATT&CK is not a risk score, compliance standard, or proof of attribution |
| NIST CSF 2.0 | Outcome-based framework for managing cybersecurity risk | Organizes Govern, Identify, Protect, Detect, Respond, and Recover activities | CSF is flexible and non-prescriptive; it does not mandate a particular product |

## Interview-ready synthesis

> I did not treat failed logons, Event 4672, or PowerShell as malicious in isolation. I correlated the same user, endpoint, source, and narrow time window, then added suspicious process ancestry and discovery commands. That supports a high-severity containment decision with moderate analytical confidence, while preserving alternate explanations and avoiding unsupported claims about malware, exfiltration, or SOX impact.
