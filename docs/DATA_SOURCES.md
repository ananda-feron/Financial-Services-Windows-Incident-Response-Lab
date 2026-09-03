# Data Sources

## EVTX-ATTACK-SAMPLES

This lab uses [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) as an external test-data dependency. The upstream project provides Windows event-log samples for detection engineering, DFIR, and threat-hunting practice and is distributed under GPL-3.0.

The third-party repository is intentionally not vendored or committed here. Clone it into the gitignored location:

```bash
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git data/raw/evtx
```

Install the parser in an isolated environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Then ingest the seven selected scenarios:

```bash
python -m ingestion.evtx_parser
```

Outputs are gitignored because they are generated from third-party binary data:

- `data/normalized/events/*.jsonl` — one normalized file per EVTX sample
- `data/events.db` — queryable SQLite event store

## Attribution and metadata boundaries

- Dataset name, source filename, upstream folder/category, and upstream CSV labels are preserved.
- The upstream README states that mappings are at ATT&CK technique level, not procedure level.
- `data/metadata/attack_samples.json` contains a separate analyst-curated current mapping for selected samples.
- Curated mappings are hypotheses to validate against event content. They do not establish intent, threat-actor identity, or a real financial-services environment.
- Westbridge Financial assets and incident narratives remain synthetic overlays; upstream host/user values are preserved in normalized evidence.

For upstream license terms and authorship, consult the cloned `LICENSE.GPL` and `README.md` or the linked source repository.
