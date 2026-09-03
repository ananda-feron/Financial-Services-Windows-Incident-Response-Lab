# EVTX Ingestion Pipeline

```text
External EVTX file
      ↓ python-evtx
Original event XML
      ↓ normalization
Stable JSON event + raw XML
      ├── JSONL analyst output
      └── SQLite events table
```

## Design decisions

1. **Use a library, not a custom binary parser.** `python-evtx` reads EVTX records and returns event XML.
2. **Keep raw evidence.** SQLite retains each record’s original XML; JSONL omits it to stay readable.
3. **Preserve provenance.** Every event stores dataset, relative source file, upstream category, curated technique, and tactic.
4. **Separate source and analysis.** Upstream labels remain in `upstream_techniques`; current curated mappings occupy dedicated fields.
5. **Make reruns idempotent.** A deterministic SHA-256 event key prevents duplicate database rows.
6. **Write JSONL atomically.** Output is written to a temporary sibling and renamed only after completion.

## Normalized schema

Important fields include `timestamp`, `event_id`, `event_record_id`, `computer`, `username`, `process_name`, `parent_process`, `command_line`, `source_ip`, `source`, `provider`, `dataset`, `source_file`, `source_category`, `attack_technique`, `attack_technique_name`, `attack_tactic`, `upstream_techniques`, and `event_data`.

Normalization uses fallbacks because Windows providers use different names for similar concepts. For example, username may appear as `User`, `TargetUserName`, or `SubjectUserName`. The untouched XML remains available when normalized fields are absent or ambiguous.

## Query examples

```bash
sqlite3 data/events.db "SELECT event_id, COUNT(*) FROM events GROUP BY event_id ORDER BY COUNT(*) DESC;"
sqlite3 data/events.db "SELECT timestamp, hostname, process_name, command_line FROM events WHERE technique_id = 'T1059.001';"
sqlite3 data/events.db "SELECT source_category, COUNT(*) FROM events GROUP BY source_category;"
```

## Current scope

This first slice stops at `EVTX → normalized JSONL → SQLite`. Detection rules, alerts, incidents, IOCs, response state, performance scoring, and the dashboard belong to later increments.
