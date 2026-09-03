"""Streaming reader for Avro object-container files, optionally gzip compressed."""

from __future__ import annotations

import gzip
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

from fastavro import reader


@contextmanager
def binary_stream(path: Path) -> Iterator[BinaryIO]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as stream:
        yield stream


def records(path: Path, limit: int | None = None) -> Iterator[dict]:
    if not path.is_file():
        raise FileNotFoundError(path)
    if limit is not None and limit < 1:
        raise ValueError("record limit must be positive")
    with binary_stream(path) as stream:
        try:
            avro = reader(stream)
            for index, record in enumerate(avro):
                if limit is not None and index >= limit:
                    break
                if not isinstance(record, dict):
                    raise ValueError(f"record {index} is not an Avro mapping")
                yield record
        except (EOFError, OSError, ValueError) as exc:
            raise ValueError(f"cannot read Avro container {path}: {exc}") from exc


def inspect_file(path: Path, limit: int = 100) -> dict:
    counts: dict[str, int] = {}
    fields: dict[str, set[str]] = {}
    seen = 0
    from tc5_ingestion.normalize import unwrap_datum
    for record in records(path, limit):
        event_type, datum = unwrap_datum(record)
        counts[event_type] = counts.get(event_type, 0) + 1
        fields.setdefault(event_type, set()).update(datum.keys())
        seen += 1
    return {"path": str(path), "records_inspected": seen, "types": counts,
            "fields": {key: sorted(value) for key, value in sorted(fields.items())}}
