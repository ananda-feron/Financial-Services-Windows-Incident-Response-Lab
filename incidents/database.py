"""Incident persistence using references to existing alerts and events."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Iterable

from incidents.models import AnalystNote, Incident, TimelineEntry

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    incident_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    description TEXT NOT NULL,
    hostname TEXT NOT NULL,
    username TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    linked_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, alert_id)
);
CREATE TABLE IF NOT EXISTS incident_evidence (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id),
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    evidence_type TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, event_id, alert_id)
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert ON incident_alerts(alert_id);
CREATE INDEX IF NOT EXISTS idx_incident_evidence_event ON incident_evidence(event_id);
CREATE INDEX IF NOT EXISTS idx_notes_incident ON notes(incident_id);
"""


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)


def persist_incidents(connection: sqlite3.Connection, incidents: Iterable[Incident]) -> tuple[int, int, int]:
    """Upsert incidents and insert unique alert/evidence links."""
    ensure_schema(connection)
    incident_count = alert_links = evidence_links = 0
    for incident in incidents:
        before = connection.total_changes
        connection.execute("""INSERT INTO incidents (
            incident_id, title, severity, status, created_at, updated_at, description,
            hostname, username, first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(incident_id) DO UPDATE SET
            title=excluded.title, severity=excluded.severity, updated_at=excluded.updated_at,
            description=excluded.description, first_seen=excluded.first_seen, last_seen=excluded.last_seen""",
        (incident.incident_id, incident.title, incident.severity, incident.status,
         incident.created_at, incident.updated_at, incident.description, incident.hostname,
         incident.username, incident.first_seen, incident.last_seen))
        if connection.total_changes > before:
            incident_count += 1
        database_incident_id = connection.execute(
            "SELECT id FROM incidents WHERE incident_id = ?", (incident.incident_id,)
        ).fetchone()[0]
        for alert in incident.alerts:
            before = connection.total_changes
            connection.execute("INSERT OR IGNORE INTO incident_alerts VALUES (?, ?, ?)",
                               (database_incident_id, alert.database_alert_id, incident.updated_at))
            if connection.total_changes > before:
                alert_links += 1
            before = connection.total_changes
            connection.execute("INSERT OR IGNORE INTO incident_evidence VALUES (?, ?, ?, ?, ?)",
                               (database_incident_id, alert.event_id, alert.database_alert_id,
                                "windows_event", incident.updated_at))
            if connection.total_changes > before:
                evidence_links += 1
    connection.commit()
    return incident_count, alert_links, evidence_links


def timeline(connection: sqlite3.Connection, incident_id: str) -> list[TimelineEntry]:
    rows = connection.execute("""SELECT
        e.timestamp, i.incident_id, a.alert_id, a.detection_id, a.severity,
        a.technique_id, a.technique_name, e.id, e.event_id, e.hostname,
        e.username, e.source_file, e.dataset
      FROM incidents i
      JOIN incident_alerts ia ON ia.incident_id = i.id
      JOIN alerts a ON a.id = ia.alert_id
      JOIN events e ON e.id = a.event_id
      WHERE i.incident_id = ? ORDER BY e.timestamp, a.alert_id""", (incident_id,)).fetchall()
    return [TimelineEntry(*row) for row in rows]


def evidence_xml(connection: sqlite3.Connection, incident_id: str, event_id: int) -> str | None:
    row = connection.execute("""SELECT e.raw_xml FROM incident_evidence ie
      JOIN incidents i ON i.id = ie.incident_id
      JOIN events e ON e.id = ie.event_id
      WHERE i.incident_id = ? AND e.id = ?""", (incident_id, event_id)).fetchone()
    return row[0] if row else None


def add_note(connection: sqlite3.Connection, incident_id: str, author: str, body: str,
             created_at: str | None = None) -> AnalystNote:
    if not author.strip() or not body.strip():
        raise ValueError("note author and body are required")
    timestamp = created_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    row = connection.execute("SELECT id FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if row is None:
        raise ValueError(f"unknown incident: {incident_id}")
    cursor = connection.execute("INSERT INTO notes (incident_id, author, body, created_at) VALUES (?, ?, ?, ?)",
                                (row[0], author.strip(), body.strip(), timestamp))
    connection.commit()
    return AnalystNote(cursor.lastrowid, incident_id, author.strip(), body.strip(), timestamp)


def notes(connection: sqlite3.Connection, incident_id: str) -> list[AnalystNote]:
    rows = connection.execute("""SELECT n.id, i.incident_id, n.author, n.body, n.created_at
      FROM notes n JOIN incidents i ON i.id = n.incident_id
      WHERE i.incident_id = ? ORDER BY n.created_at, n.id""", (incident_id,)).fetchall()
    return [AnalystNote(*row) for row in rows]
