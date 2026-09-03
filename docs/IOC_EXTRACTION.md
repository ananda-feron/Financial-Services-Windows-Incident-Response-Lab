# IOC Extraction

## Phase 4A boundary

This increment implements `incident → normalized event → extracted IOC → SQLite`. It does not perform threat-intelligence enrichment, execute or record response actions, transition incident status, calculate detection metrics, or add dashboard features.

## Analytical terminology

The database uses the familiar term **IOC**, but extraction alone produces an **observable**, not proof of compromise. A hostname, username, process, file path, hash, IP address, domain, or command line becomes meaningful only after validation against incident context, organizational baselines, and other evidence.

## Sources

Values are extracted only from normalized `events` rows referenced by `incident_evidence`. The extractor does not read incident titles, descriptions, analyst notes, or manually supplied IOC lists.

Supported types:

| Type | Normalized sources |
|---|---|
| IP | Source/destination IP fields validated with Python's IP-address parser |
| Hostname | Event computer and explicit source/destination/workstation fields |
| Username | Normalized user and Windows subject/target user fields |
| Process | Basenames derived from normalized and provider-specific image fields |
| Command line | Normalized command line, parent command line, or script-block text |
| File path | Explicit Windows image, target filename, path, and loaded-image fields |
| Hash | Labeled MD5, SHA-1, SHA-256, and import-hash values |
| Domain | Explicit hostname fields and domains in HTTP/HTTPS URLs |

Domain extraction deliberately avoids treating dotted PowerShell/.NET method names as DNS domains.

## Deduplication and provenance

IOC identity is the SHA-256-derived combination of:

```text
incident ID + IOC type + normalized value
```

The `iocs` table stores the first observation and enforces that uniqueness rule. The `ioc_sightings` table separately links every supporting event and source field. This prevents duplicate IOC rows without discarding repeated evidence.

The evidence chain is:

```text
IOC → first event + all sightings → original event XML → source EVTX → dataset
```

## Run

Extract indicators for every persisted incident:

```bash
python -m ioc.extractor
```

Limit extraction to one or more incidents:

```bash
python -m ioc.extractor --incident INC-XXXXXXXXXX
```

Inspect counts:

```bash
sqlite3 data/events.db "SELECT type, COUNT(*) FROM iocs GROUP BY type ORDER BY type;"
```

Rerunning extraction creates no duplicate IOC rows or sightings.
