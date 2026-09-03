"""SQLite persistence for normalized Windows events."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    event_key TEXT NOT NULL UNIQUE,
    timestamp TEXT,
    hostname TEXT,
    username TEXT,
    event_id INTEGER NOT NULL,
    event_record_id TEXT,
    process_name TEXT,
    parent_process TEXT,
    command_line TEXT,
    source_ip TEXT,
    source TEXT,
    provider TEXT,
    source_file TEXT NOT NULL,
    source_category TEXT,
    dataset TEXT NOT NULL,
    technique_id TEXT,
    technique_name TEXT,
    tactic TEXT,
    upstream_techniques_json TEXT NOT NULL,
    event_data_json TEXT NOT NULL,
    raw_xml TEXT NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(hostname);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_events_technique ON events(technique_id);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript(SCHEMA)
    return connection


def event_key(event: dict[str, Any]) -> str:
    identity = "|".join(str(event.get(field, "")) for field in (
        "dataset", "source_file", "event_record_id", "record_index", "timestamp", "event_id"
    ))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def insert_events(connection: sqlite3.Connection, events: Iterable[dict[str, Any]]) -> tuple[int, int]:
    inserted = skipped = 0
    sql = """INSERT OR IGNORE INTO events (
        event_key, timestamp, hostname, username, event_id, event_record_id,
        process_name, parent_process, command_line, source_ip, source, provider,
        source_file, source_category, dataset, technique_id, technique_name, tactic,
        upstream_techniques_json, event_data_json, raw_xml
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    for event in events:
        before = connection.total_changes
        connection.execute(sql, (
            event_key(event), event.get("timestamp"), event.get("computer"), event.get("username"),
            event["event_id"], event.get("event_record_id"), event.get("process_name"),
            event.get("parent_process"), event.get("command_line"), event.get("source_ip"),
            event.get("source"), event.get("provider"), event["source_file"],
            event.get("source_category"), event["dataset"], event.get("attack_technique"),
            event.get("attack_technique_name"), event.get("attack_tactic"),
            json.dumps(event.get("upstream_techniques", []), sort_keys=True),
            json.dumps(event.get("event_data", {}), sort_keys=True), event["raw_xml"],
        ))
        if connection.total_changes > before:
            inserted += 1
        else:
            skipped += 1
    connection.commit()
    return inserted, skipped
