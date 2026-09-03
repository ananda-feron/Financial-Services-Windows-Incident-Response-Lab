# Detection and Incident Metrics Methodology

Phase 5 derives repeatable measurements from the SQLite evidence model and versioned rule/ground-truth metadata. It does not store dashboard snapshots or hard-code expected totals.

## Detection metrics

The report counts normalized events, enabled YAML rules, potential rule evaluations (`events × enabled rules`), persisted alerts, and alert distributions. “Rules evaluated” is a deterministic evaluation opportunity count, not runtime-performance instrumentation.

`data/metadata/detection_ground_truth.json` identifies expected rule outcomes for specifically labeled positive samples. Actual outcomes are unique `source_file + detection_id` pairs, so repeated matching events do not inflate effectiveness. Missing and unexpected pairs remain visible.

Recall is reported for these positive expectations. Precision, F1, and false-positive rate remain `null`: seven attack-oriented samples do not provide a representative benign denominator or enterprise base rate.

## ATT&CK coverage

Coverage asks whether a technique identified in the ground-truth telemetry has an enabled rule and a persisted detection. “Observed” therefore means explicitly labeled for this detection-validation scope, not merely inferred from an upstream folder name. Rule mappings remain separate from event and upstream mappings.

## Incident and response metrics

The report derives incident totals and severity, plus per-incident averages for linked alerts, evidence, IOCs, and response actions. Response actions are grouped by their actual stored status; no sample counts are invented.

## Provenance coverage

Traceability is calculated independently for:

- alerts linked to events with dataset, source file, and original XML;
- incident evidence linked to valid event and alert rows;
- events retaining dataset, source file, and original XML;
- response actions with at least one evidence link.

An empty category reports `null`, not 100%, because there is nothing applicable to measure. A percentage measures referential completeness, not evidence quality or maliciousness.

## Current-data caveat

Metrics always report current database state. If ingestion or detection is rerun against changed rules or samples, totals may differ from earlier documentation. Unexpected ground-truth results should prompt rule or label review rather than being silently forced to match a narrative.
