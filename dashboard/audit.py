"""Append-only analyst UI audit events."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY,
  analyst TEXT NOT NULL,
  role TEXT NOT NULL,
  action TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_object ON audit_log(object_type, object_id);
"""


def record(connection: sqlite3.Connection, analyst: str, role: str, action: str,
           object_type: str, object_id: str) -> None:
    connection.executescript(SCHEMA)
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    connection.execute("INSERT INTO audit_log (analyst,role,action,object_type,object_id,created_at) VALUES (?,?,?,?,?,?)",
                       (analyst, role, action, object_type, object_id, timestamp))
    connection.commit()
