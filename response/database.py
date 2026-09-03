"""Persistence and provenance queries for simulated response actions."""

from __future__ import annotations

import sqlite3

from response.models import ResponseAction

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS response_actions (
    id INTEGER PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    normalized_target TEXT NOT NULL,
    status TEXT NOT NULL,
    rationale TEXT NOT NULL,
    analyst TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(incident_id, action_type, normalized_target)
);
CREATE TABLE IF NOT EXISTS action_evidence (
    action_id INTEGER NOT NULL REFERENCES response_actions(id) ON DELETE CASCADE,
    incident_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    alert_id INTEGER NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY(action_id, incident_id, event_id, alert_id),
    FOREIGN KEY(incident_id, event_id, alert_id)
        REFERENCES incident_evidence(incident_id, event_id, alert_id)
);
CREATE INDEX IF NOT EXISTS idx_response_actions_incident ON response_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions(status);
CREATE INDEX IF NOT EXISTS idx_action_evidence_alert ON action_evidence(alert_id);
CREATE INDEX IF NOT EXISTS idx_action_evidence_event ON action_evidence(event_id);
"""


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)


def row_to_action(row: tuple) -> ResponseAction:
    return ResponseAction(*row)


def get_action(connection: sqlite3.Connection, action_id: str) -> ResponseAction | None:
    row = connection.execute("""SELECT r.action_id, i.incident_id, r.action_type,
      r.target, r.status, r.rationale, r.analyst, r.created_at, r.updated_at
      FROM response_actions r JOIN incidents i ON i.id = r.incident_id
      WHERE r.action_id = ?""", (action_id,)).fetchone()
    return row_to_action(row) if row else None


def trace_action(connection: sqlite3.Connection, action_id: str) -> dict | None:
    """Trace a decision through evidence, alerts, events, and original EVTX XML."""
    action = get_action(connection, action_id)
    if action is None:
        return None
    connection.row_factory = sqlite3.Row
    rows = connection.execute("""SELECT a.alert_id, e.id AS event_id,
      e.event_id AS windows_event_id, e.timestamp, e.hostname, e.source_file,
      e.dataset, e.raw_xml
      FROM response_actions r
      JOIN action_evidence ae ON ae.action_id = r.id
      JOIN alerts a ON a.id = ae.alert_id
      JOIN events e ON e.id = ae.event_id
      WHERE r.action_id = ? ORDER BY e.timestamp, a.alert_id""", (action_id,)).fetchall()
    return {"action": action, "evidence": [dict(row) for row in rows]}
