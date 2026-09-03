"""Parse selected EVTX-ATTACK-SAMPLES into JSONL and SQLite.

Run from the repository root:
    python -m ingestion.evtx_parser
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

from ingestion.database import connect, insert_events
from ingestion.metadata import enrich, load_manifest, load_upstream_csv
from ingestion.normalize import normalize_event

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data" / "raw" / "evtx"
DEFAULT_MANIFEST = ROOT / "data" / "metadata" / "attack_samples.json"
DEFAULT_OUTPUT = ROOT / "data" / "normalized" / "events"
DEFAULT_DATABASE = ROOT / "data" / "events.db"


def iter_record_xml(path: Path) -> Iterable[str]:
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        raise RuntimeError("python-evtx is required; run: pip install -r requirements.txt") from exc
    with Evtx(str(path)) as log:
        for record in log.records():
            yield record.xml()


def safe_output_name(source_file: str) -> str:
    return source_file.replace("\\", "_").replace("/", "_").removesuffix(".evtx") + ".jsonl"


def parse_sample(path: Path, metadata: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    normalized: list[dict[str, Any]] = []
    errors = 0
    for index, xml in enumerate(iter_record_xml(path), 1):
        try:
            normalized.append(normalize_event(xml, metadata, index))
        except (ValueError, TypeError):
            errors += 1
    return normalized, errors


def write_jsonl(path: Path, events: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for event in events:
            portable = {key: value for key, value in event.items() if key != "raw_xml"}
            handle.write(json.dumps(portable, sort_keys=True) + "\n")
    temporary.replace(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="cloned dataset root")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="selected sample manifest")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="normalized JSONL directory")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE, help="SQLite database path")
    parser.add_argument("--limit", type=int, help="process only the first N manifest samples")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 1:
        print("error: --limit must be at least 1", file=sys.stderr)
        return 2
    if not args.input.exists():
        print("error: dataset not found. Follow docs/DATA_SOURCES.md to clone it.", file=sys.stderr)
        return 2
    try:
        samples = load_manifest(args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot load manifest: {exc}", file=sys.stderr)
        return 2
    if args.limit:
        samples = samples[:args.limit]
    upstream = load_upstream_csv(args.input / "evtx_data.csv")
    connection = connect(args.database)
    totals = {"samples": 0, "events": 0, "errors": 0, "inserted": 0, "duplicates": 0}
    try:
        for sample in samples:
            metadata = enrich(sample, upstream)
            source = args.input / sample["source_file"]
            if not source.is_file():
                print(f"warning: missing sample: {sample['source_file']}", file=sys.stderr)
                totals["errors"] += 1
                continue
            try:
                events, errors = parse_sample(source, metadata)
            except (OSError, RuntimeError) as exc:
                print(f"error: {sample['source_file']}: {exc}", file=sys.stderr)
                totals["errors"] += 1
                continue
            write_jsonl(args.output / safe_output_name(sample["source_file"]), events)
            inserted, duplicates = insert_events(connection, events)
            totals["samples"] += 1
            totals["events"] += len(events)
            totals["errors"] += errors
            totals["inserted"] += inserted
            totals["duplicates"] += duplicates
            print(f"{sample['source_file']}: {len(events)} events, {errors} normalization errors")
    finally:
        connection.close()
    print(json.dumps(totals, indent=2))
    return 1 if totals["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
