"""Normalize CDM20 records without forcing them into the EVTX event model."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def unwrap_datum(record: dict) -> tuple[str, dict]:
    datum = record.get("datum", record)
    if isinstance(datum, dict) and len(datum) == 1:
        key, value = next(iter(datum.items()))
        if isinstance(value, dict) and ("." in key or key in {"Event", "Subject", "FileObject", "NetFlowObject", "Principal"}):
            return key.rsplit(".", 1)[-1], value
    if not isinstance(datum, dict):
        raise ValueError("CDM datum must be a mapping")
    if "timestampNanos" in datum and "subject" in datum: kind = "Event"
    elif "localAddress" in datum or "remoteAddress" in datum: kind = "NetFlowObject"
    elif "username" in datum or "userId" in datum: kind = "Principal"
    elif "parentSubject" in datum or "cmdLine" in datum: kind = "Subject"
    elif "baseObject" in datum or "fileDescriptor" in datum: kind = "FileObject"
    else: kind = "Unknown"
    return kind, datum


def scalar(value: Any) -> str | None:
    if value is None: return None
    if isinstance(value, bytes): return value.hex()
    if isinstance(value, dict):
        for key in ("com.bbn.tc.schema.avro.cdm20.UUID", "UUID", "string", "value"):
            if key in value: return scalar(value[key])
        return json.dumps(value, sort_keys=True, default=str)
    return str(value)


def timestamp(value: Any) -> str | None:
    if value is None: return None
    try:
        nanos = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid timestampNanos: {value}") from exc
    return datetime.fromtimestamp(nanos / 1_000_000_000, timezone.utc).isoformat().replace("+00:00", "Z")


def normalize(record: dict, dataset_id: str, stream_id: str, source_file: str,
              record_index: int) -> dict:
    event_type, datum = unwrap_datum(record)
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=lambda value: value.hex() if isinstance(value, bytes) else str(value))
    source_id = scalar(datum.get("uuid")) or hashlib.sha256(canonical.encode()).hexdigest()
    properties = datum.get("properties") if isinstance(datum.get("properties"), dict) else {}
    return {
        "source_event_id": source_id, "dataset_id": dataset_id, "stream_id": stream_id,
        "event_type": event_type, "timestamp": timestamp(datum.get("timestampNanos")),
        "host": scalar(datum.get("hostId") or properties.get("host")),
        "principal": scalar(datum.get("localPrincipal") or datum.get("principal") or datum.get("username")),
        "process": scalar(datum.get("subject") or datum.get("parentSubject") or datum.get("cmdLine")),
        "file": scalar(datum.get("predicateObject") if event_type == "Event" else datum.get("baseObject")),
        "network": scalar(datum.get("remoteAddress") or datum.get("localAddress")),
        "raw_event_reference": f"{source_file}#record={record_index}",
        "raw_sha256": hashlib.sha256(canonical.encode()).hexdigest(), "raw_event_json": canonical,
    }
