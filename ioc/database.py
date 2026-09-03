"""Persist deduplicated IOCs while retaining every event sighting."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Iterable

from ioc.models import IOCObservation

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY,
    ioc_id TEXT NOT NULL UNIQUE,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id),
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(incident_id, type, normalized_value)
);
CREATE TABLE IF NOT EXISTS ioc_sightings (
    ioc_id INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id),
    source TEXT NOT NULL,
    observed_at TEXT,
    PRIMARY KEY(ioc_id, event_id, source)
);
CREATE INDEX IF NOT EXISTS idx_iocs_incident ON iocs(incident_id);
CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, normalized_value);
CREATE INDEX IF NOT EXISTS idx_ioc_sightings_event ON ioc_sightings(event_id);
"""


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)


def deterministic_ioc_id(incident_id: str, ioc_type: str, normalized_value: str) -> str:
    identity = f"{incident_id}|{ioc_type}|{normalized_value}"
    return "IOC-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()


def persist_observations(connection: sqlite3.Connection, observations: Iterable[IOCObservation]) -> tuple[int, int, int]:
    """Return new IOCs, duplicate IOCs, and new event sightings."""
    ensure_schema(connection)
    inserted = duplicates = sightings = 0
    for item in observations:
        incident = connection.execute("SELECT id FROM incidents WHERE incident_id = ?", (item.incident_id,)).fetchone()
        if incident is None:
            raise ValueError(f"unknown incident: {item.incident_id}")
        ioc_id = deterministic_ioc_id(item.incident_id, item.ioc_type, item.normalized_value)
        before = connection.total_changes
        connection.execute("""INSERT OR IGNORE INTO iocs (
          ioc_id, incident_id, event_id, type, value, normalized_value, source, first_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (
            ioc_id, incident[0], item.event_id, item.ioc_type, item.value,
            item.normalized_value, item.source, item.first_seen,
        ))
        if connection.total_changes > before:
            inserted += 1
        else:
            duplicates += 1
        database_ioc_id = connection.execute("SELECT id FROM iocs WHERE ioc_id = ?", (ioc_id,)).fetchone()[0]
        before = connection.total_changes
        connection.execute("INSERT OR IGNORE INTO ioc_sightings VALUES (?, ?, ?, ?)",
                           (database_ioc_id, item.event_id, item.source, item.first_seen))
        if connection.total_changes > before:
            sightings += 1
    connection.commit()
    return inserted, duplicates, sightings


def trace_ioc(connection: sqlite3.Connection, ioc_id: str) -> dict | None:
    connection.row_factory = sqlite3.Row
    row = connection.execute("""SELECT o.ioc_id, i.incident_id, o.type, o.value,
      o.first_seen, e.id AS event_id, e.event_id AS windows_event_id,
      e.source_file, e.dataset, e.raw_xml
      FROM iocs o JOIN incidents i ON i.id = o.incident_id
      JOIN events e ON e.id = o.event_id WHERE o.ioc_id = ?""", (ioc_id,)).fetchone()
    return dict(row) if row else None
