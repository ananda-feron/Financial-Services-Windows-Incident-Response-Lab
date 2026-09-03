"""Alert persistence linked to normalized events without evidence duplication."""

from __future__ import annotations

import json
import sqlite3
from typing import Iterable

from detection_engine.models import Alert

ALERT_SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    alert_id TEXT NOT NULL UNIQUE,
    detection_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    event_id INTEGER NOT NULL REFERENCES events(id),
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    curated_by TEXT NOT NULL,
    curated_at TEXT NOT NULL,
    mapping_rationale TEXT NOT NULL,
    event_curated_mapping_json TEXT NOT NULL,
    upstream_mappings_json TEXT NOT NULL,
    UNIQUE(detection_id, rule_version, event_id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_detection ON alerts(detection_id);
CREATE INDEX IF NOT EXISTS idx_alerts_event ON alerts(event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
"""


def ensure_alert_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(ALERT_SCHEMA)


def insert_alerts(connection: sqlite3.Connection, alerts: Iterable[Alert]) -> tuple[int, int]:
    ensure_alert_schema(connection)
    inserted = skipped = 0
    sql = """INSERT OR IGNORE INTO alerts (
        alert_id, detection_id, rule_version, event_id, severity, confidence,
        technique_id, technique_name, tactic, status, created_at, curated_by,
        curated_at, mapping_rationale, event_curated_mapping_json, upstream_mappings_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    for alert in alerts:
        before = connection.total_changes
        connection.execute(sql, (
            alert.alert_id, alert.detection_id, alert.rule_version, alert.event_id,
            alert.severity, alert.confidence, alert.technique_id, alert.technique_name,
            alert.tactic, alert.status, alert.created_at, alert.curated_by,
            alert.curated_at, alert.mapping_rationale,
            json.dumps(alert.event_curated_mapping, sort_keys=True),
            json.dumps(alert.upstream_mappings, sort_keys=True),
        ))
        if connection.total_changes > before:
            inserted += 1
        else:
            skipped += 1
    connection.commit()
    return inserted, skipped


def reconcile_alerts(connection: sqlite3.Connection, rule_identities: Iterable[tuple[str, str]],
                     current_alert_ids: Iterable[str]) -> int:
    """Mark persisted outcomes that no longer match their current rule version stale."""
    identities = tuple(rule_identities)
    current = tuple(current_alert_ids)
    before = connection.total_changes
    for detection_id, version in identities:
        connection.execute("UPDATE alerts SET status='stale' WHERE detection_id=? AND rule_version=?",
                           (detection_id, version))
    if current:
        placeholders = ",".join("?" for _ in current)
        connection.execute(f"UPDATE alerts SET status='new' WHERE alert_id IN ({placeholders})", current)
    connection.commit()
    return connection.total_changes - before


def trace_alert(connection: sqlite3.Connection, alert_id: str) -> dict | None:
    """Trace an alert through its event to dataset and original EVTX source."""
    connection.row_factory = sqlite3.Row
    row = connection.execute("""SELECT
        a.alert_id, a.detection_id, a.rule_version, a.technique_id AS rule_technique_id,
        a.severity, a.status, e.id AS event_id, e.event_key, e.event_id AS windows_event_id,
        e.timestamp, e.hostname, e.dataset, e.source_file, e.source_category,
        e.curated_technique_id, e.curated_technique_name,
        e.upstream_techniques_json
      FROM alerts a JOIN events e ON e.id = a.event_id WHERE a.alert_id = ?""", (alert_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["upstream_techniques"] = json.loads(result.pop("upstream_techniques_json"))
    return result
