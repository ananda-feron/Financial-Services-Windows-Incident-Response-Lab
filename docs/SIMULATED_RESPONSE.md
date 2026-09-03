# Simulated Incident Response

Phase 4B adds evidence-backed response decisions without connecting to endpoints, identity systems, firewalls, or other infrastructure. Every completed action has the explicit status `SIMULATED`; it represents an analyst exercise, not a real-world execution.

## Supported actions

| Action | Intended decision |
| --- | --- |
| `ISOLATE_HOST` | Contain a potentially compromised endpoint |
| `DISABLE_ACCOUNT` | Limit use of a potentially compromised identity |
| `BLOCK_INDICATOR` | Model a preventive control for a reviewed observable |
| `TERMINATE_PROCESS` | Model stopping a suspicious process |
| `COLLECT_ARTIFACT` | Preserve additional material for investigation |

Actions progress through `PLANNED → APPROVED → SIMULATED`, or may become `CANCELLED` before simulation. Target, rationale, analyst, and at least one alert already linked to the incident as evidence are mandatory.

## Evidence provenance

The response layer references the existing composite evidence identity rather than copying alert, event, IOC, or XML content:

```text
Response action
  └── action_evidence
        └── incident_evidence
              ├── alert
              └── normalized event
                    └── original EVTX source and XML
```

This answers why an action was recommended while preserving the evidence chain. An extracted observable may inform the analyst's target, but it is not automatically treated as malicious and is not duplicated into the action record.

## Incident lifecycle

Allowed transitions are:

```text
NEW → TRIAGING → INVESTIGATING → CONTAINED → ERADICATION
    → RECOVERY → RESOLVED → CLOSED
```

`CONTAINED` requires a `SIMULATED` containment action belonging to the same incident. Simulating `COLLECT_ARTIFACT` does not imply containment. Invalid state changes are rejected, and action approval is required before simulation.

## Safety boundary

The implementation performs SQLite writes only. It contains no endpoint, Active Directory/Entra ID, EDR, firewall, network, shell-execution, or threat-intelligence integration. Production response would additionally require authorization controls, separation of duties, rollback procedures, audit retention, and tool-specific error handling.
