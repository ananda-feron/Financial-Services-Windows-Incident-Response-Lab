# Risk Assessment

## Method and rating

Likelihood and impact use Low (1), Medium (2), High (3); overall score is their product: 1–2 Low, 3–4 Medium, 6–9 High.

- Likelihood: **Medium (2)** — independent telemetry supports misuse, but important identity/network context is absent.
- Impact: **High (3)** — a Finance/Risk endpoint may hold sensitive information; sensitive privileges increase possible blast radius.
- Overall: **High (6/9)**.

| Finding | Security impact | Business risk | Evidence strength |
|---|---|---|---|
| Failure burst then success | Possible credential misuse | Unauthorized access | High within dataset |
| Office-spawned PowerShell | User-context execution | Endpoint compromise/interruption | High |
| Account/process discovery | Reconnaissance | Enables further compromise | Medium |
| Event 4672 | Sensitive token assigned | Potentially greater blast radius | Medium; privilege list absent |
| Limited telemetry | Reduced assurance | Delayed scoping/decisions | High |

## CIA and control implications

- Confidentiality: High potential impact from nonpublic finance/risk data exposure.
- Integrity: High potential impact if forecasts, control evidence, or risk reporting were altered.
- Availability: Medium potential impact from isolation and investigation downtime.
- SOX: This incident does **not** automatically constitute a deficiency. Control owners must assess whether financially relevant identity, access, change, or monitoring controls failed and whether compensating controls operated.

After containment, credential rotation, endpoint rebuild, MFA assurance, centralized logging, and tuned detection, target residual risk is **Medium (1 × 3 = 3/9)**. Business impact remains high; controls reduce likelihood and time to detect.

Raise severity if evidence confirms privileged lateral movement, regulated-data access, financial record modification, persistence, or exfiltration. Lower confidence if VPN ownership, approved support records, and user verification establish authorized activity.
