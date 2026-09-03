"""Read models for analyst dashboard pages."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from metrics.attack_coverage import attack_coverage
from metrics.database import table_exists
from metrics.detection_metrics import detection_metrics, detection_performance
from metrics.incident_metrics import incident_metrics, provenance_metrics


def rows(connection: sqlite3.Connection, query: str, parameters=()) -> list[dict[str, Any]]:
    connection.row_factory = sqlite3.Row
    return [dict(row) for row in connection.execute(query, parameters).fetchall()]


def overview(connection: sqlite3.Connection, rules: Path, truth: Path) -> dict[str, Any]:
    detection = detection_metrics(connection, rules)
    incidents = incident_metrics(connection)
    provenance = provenance_metrics(connection)
    coverage = attack_coverage(connection, rules, truth)
    recent = rows(connection, "SELECT incident_id,title,severity,status,hostname,updated_at FROM incidents ORDER BY updated_at DESC LIMIT 8") if table_exists(connection, "incidents") else []
    return {"detection": detection, "incidents": incidents, "provenance": provenance,
            "coverage": coverage, "recent_incidents": recent}


def detections(connection: sqlite3.Connection, truth: Path) -> dict[str, Any]:
    performance = detection_performance(connection, truth)
    alerts = rows(connection, """SELECT detection_id,rule_version,technique_id,technique_name,
      severity,COUNT(*) alert_count FROM alerts WHERE status <> 'stale'
      GROUP BY detection_id,rule_version,technique_id,technique_name,severity ORDER BY detection_id""") if table_exists(connection, "alerts") else []
    return {"rules": alerts, "performance": performance}


def incident_list(connection: sqlite3.Connection, filters: dict[str, str]) -> list[dict[str, Any]]:
    if not table_exists(connection, "incidents"):
        return []
    clauses, values = ["1=1"], []
    mappings = {"severity": "i.severity", "status": "i.status", "host": "i.hostname",
                "user": "i.username", "tactic": "a.tactic", "technique": "a.technique_id",
                "detection": "a.detection_id"}
    for key, column in mappings.items():
        if filters.get(key):
            clauses.append(f"{column} = ?")
            values.append(filters[key])
    if filters.get("from"):
        clauses.append("i.first_seen >= ?"); values.append(filters["from"])
    if filters.get("to"):
        clauses.append("i.last_seen <= ?"); values.append(filters["to"])
    return rows(connection, f"""SELECT DISTINCT i.incident_id,i.title,i.severity,i.status,
      i.hostname,i.username,i.first_seen,i.last_seen FROM incidents i
      LEFT JOIN incident_alerts ia ON ia.incident_id=i.id LEFT JOIN alerts a ON a.id=ia.alert_id
      WHERE {' AND '.join(clauses)} ORDER BY i.last_seen DESC""", values)


def incident_detail(connection: sqlite3.Connection, incident_id: str) -> dict[str, Any] | None:
    incidents = rows(connection, "SELECT * FROM incidents WHERE incident_id=?", (incident_id,))
    if not incidents:
        return None
    database_id = incidents[0]["id"]
    alerts = rows(connection, """SELECT a.* FROM incident_alerts ia JOIN alerts a ON a.id=ia.alert_id
      WHERE ia.incident_id=? ORDER BY a.created_at""", (database_id,))
    evidence = rows(connection, """SELECT e.id,e.event_id,e.timestamp,e.hostname,e.username,e.source_file,
      e.dataset,e.raw_xml,a.alert_id FROM incident_evidence ie JOIN events e ON e.id=ie.event_id
      JOIN alerts a ON a.id=ie.alert_id WHERE ie.incident_id=? ORDER BY e.timestamp""", (database_id,))
    optional = {}
    for table, query in {
        "iocs": "SELECT ioc_id,type,value,source,first_seen FROM iocs WHERE incident_id=? ORDER BY type,value",
        "actions": "SELECT action_id,action_type,target,status,rationale,analyst,created_at FROM response_actions WHERE incident_id=? ORDER BY created_at",
        "notes": "SELECT author,body,created_at FROM notes WHERE incident_id=? ORDER BY created_at",
    }.items():
        optional[table] = rows(connection, query, (database_id,)) if table_exists(connection, table) else []
    return {"incident": incidents[0], "alerts": alerts, "evidence": evidence, **optional}


def search(connection: sqlite3.Connection, term: str) -> list[dict[str, str]]:
    if not term.strip():
        return []
    pattern = f"%{term.strip()}%"; results = []
    queries = [
        ("incident", "SELECT incident_id id,title label FROM incidents WHERE incident_id LIKE ? OR hostname LIKE ? OR username LIKE ?", 3),
        ("alert", "SELECT alert_id id,detection_id || ' · ' || technique_id label FROM alerts WHERE status <> 'stale' AND (alert_id LIKE ? OR detection_id LIKE ? OR technique_id LIKE ?)", 3),
        ("event", "SELECT CAST(id AS TEXT) id,hostname || ' · Event ' || event_id label FROM events WHERE hostname LIKE ? OR username LIKE ? OR command_line LIKE ?", 3),
        ("ioc", "SELECT ioc_id id,type || ' · ' || value label FROM iocs WHERE value LIKE ? OR type LIKE ?", 2),
    ]
    for kind, query, arity in queries:
        table = {"incident": "incidents", "alert": "alerts", "event": "events", "ioc": "iocs"}[kind]
        if table_exists(connection, table):
            results.extend({"kind": kind, **item} for item in rows(connection, query, (pattern,) * arity))
    return results[:100]
