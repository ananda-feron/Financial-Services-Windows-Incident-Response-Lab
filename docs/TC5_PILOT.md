# DARPA TC5 Windows Pilot

This pilot adds a second, deliberately separate ingestion path for DARPA Transparent Computing Engagement 5 CDM20 provenance telemetry. TC5 is public telemetry from a controlled enterprise attack exercise—not organic production financial-services logs.

## Selected scope

The registry selects the FiveDirections instance-1 stream and first compressed shard, `ta1-fivedirections-1-e5-official-1.bin.1.gz`. The public Drive listing identifies that shard as approximately 291.3 MB compressed. Raw data and the generated `data/tc5.db` are ignored by Git.

The upstream Google Drive currently returns a quota-exceeded response for the shard, CDM20 schema, checksum manifest, and ground-truth PDF. Consequently, production code and tests are complete, but live-shard validation remains explicitly pending. No synthetic fixture is represented as DARPA data.

## Pipeline

```text
TC5 CDM20 Avro → streaming reader → CDM extraction
  → TC5 normalized records → separate SQLite tables
  → source provenance + separate ground-truth references
```

The TC5 schema preserves source UUID, dataset and stream identities, CDM record type, nanosecond timestamp, host/principal/process/file/network references, source shard and record index, raw-event SHA-256, and canonical raw JSON. It does not reuse the EVTX event table.

## Commands

Place the official shard under `data/raw/tc5/` after it becomes available, then run:

```bash
python -m tc5_ingestion inspect --input data/raw/tc5/ta1-fivedirections-1-e5-official-1.bin.1.gz
python -m tc5_ingestion normalize --input data/raw/tc5/ta1-fivedirections-1-e5-official-1.bin.1.gz --limit 10000
python -m tc5_ingestion validate
```

The record limit bounds the pilot. Expand only after inspecting real CDM types and resolving entity references across the selected stream.

## Ground-truth boundary

`ground_truth/tc5_windows_pilot.json` stores attack windows, technique annotations, and source references separately. Its windows and techniques remain empty until they can be transcribed and verified against the official report. The implementation never labels every event malicious and makes no TC5 detection-coverage claim.

## Sources

- [DARPA Transparent Computing release](https://github.com/darpa-i2o/Transparent-Computing)
- [COMIDDS TC5 profile](https://fkie-cad.github.io/COMIDDS/content/datasets/darpa_tc5/)
- [Official TC5 data folder](https://drive.google.com/drive/folders/1okt4AYElyBohW4XiOBqmsvjwXsnUjLVf)
