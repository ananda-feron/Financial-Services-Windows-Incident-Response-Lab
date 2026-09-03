"""Resolve curated and upstream EVTX-ATTACK-SAMPLES metadata."""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

TECHNIQUE = re.compile(r"technique_id=(T\d+(?:\.\d+)?)\s*,\s*technique_name=([^,]+)", re.I)


def load_manifest(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    samples = payload.get("samples")
    if not isinstance(samples, list):
        raise ValueError(f"{path}: expected a 'samples' list")
    return samples


def load_upstream_csv(path: Path) -> dict[str, dict[str, Any]]:
    """Aggregate the upstream CSV by filename, preserving its original labels."""
    index: dict[str, dict[str, Any]] = defaultdict(lambda: {"tactics": set(), "techniques": set()})
    if not path.exists():
        return {}
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        for row in csv.DictReader(handle):
            filename = row.get("EVTX_FileName")
            if not filename:
                continue
            if row.get("EVTX_Tactic"):
                index[filename]["tactics"].add(row["EVTX_Tactic"])
            match = TECHNIQUE.search(row.get("RuleName", ""))
            if match:
                index[filename]["techniques"].add((match.group(1).upper(), match.group(2).strip()))
    return {
        name: {"tactics": sorted(item["tactics"]),
               "techniques": [{"id": tid, "name": label} for tid, label in sorted(item["techniques"])]}
        for name, item in index.items()
    }


def enrich(sample: dict[str, Any], upstream: dict[str, dict[str, Any]]) -> dict[str, Any]:
    enriched = dict(sample)
    enriched.setdefault("dataset", "EVTX-ATTACK-SAMPLES")
    enriched.setdefault("curated_by", "Project analyst")
    enriched.setdefault("curated_at", "2026-09-03")
    original = upstream.get(Path(sample["source_file"]).name, {})
    enriched["upstream_tactics"] = original.get("tactics", [])
    enriched["upstream_techniques"] = original.get("techniques", [])
    return enriched
