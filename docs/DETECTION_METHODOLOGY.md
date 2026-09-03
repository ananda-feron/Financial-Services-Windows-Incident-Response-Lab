# Detection Methodology

## Phase 2 boundary

This phase implements `normalized event → YAML rule → ATT&CK-mapped alert → SQLite`. It does not create incidents, response workflows, performance claims, or a dashboard.

## Responsibilities

- `loader.py` validates YAML and constructs immutable rule models.
- `engine.py` evaluates normalized events and constructs alert objects.
- `database.py` stores alert references and traces them back to evidence.
- YAML files contain behavior conditions and rule ATT&CK mappings; they are not the ATT&CK source of truth.

Supported deterministic operators are `equals`, `in`, `contains`, `contains_any`, `ends_with`, and `exists`, composed through `all`, `any`, and `not`. String comparison is case-insensitive by default.

## Rules

| Rule | Behavior | ATT&CK | Severity | Key limitation |
|---|---|---|---|---|
| DET-001 v1.0 | PowerShell telemetry plus suspicious command characteristics | T1059.001 | High | PowerShell is dual-use; tune approved automation |
| DET-002 v1.0 | WMI Provider Host spawning a process | T1047 | High | Legitimate administration can create this relationship |
| DET-003 v1.0 | PowerShell accessing LSASS with observed access mask | T1003.001 | Critical | Process access does not prove successful credential extraction |

Severity represents potential consequence; confidence represents how strongly the telemetry supports the detection behavior. Neither field alone confirms malicious intent.

## Provenance chain

```text
Alert ID
  → Detection ID + rule version + current rule mapping
  → SQLite event ID
  → Event curated mapping + upstream legacy mapping
  → Dataset + relative EVTX source file
  → Preserved original XML
```

Alerts do not copy full event content. The `alerts.event_id` foreign key points to `events.id`. A SHA-256-derived alert identity plus the database uniqueness constraint prevents duplicate alerts for the same rule version and event.

## Run

```bash
python -m detection_engine.engine
python -m detection_engine.engine --output data/alerts.json
```

Rerunning the same rule version reports matches but inserts no duplicate alert rows.

## Rule changes

Never silently change the meaning of a released rule. Increment `version` when logic, severity, confidence, or ATT&CK mapping changes. Existing alerts retain the exact rule version that generated them.
