"""Incident, IOC, response, and evidence-provenance metrics."""

from __future__ import annotations

import sqlite3
from typing import Any

from metrics.database import average_query, count, grouped_counts, percentage, table_exists


def incident_metrics(connection: sqlite3.Connection) -> dict[str, Any]:
    incidents = count(connection, "incidents")
    result = {
        "total_incidents": incidents,
        "incidents_by_severity": grouped_counts(connection, "incidents", "severity"),
        "alerts_per_incident": None,
        "evidence_per_incident": None,
        "iocs_per_incident": None,
        "response_actions_per_incident": None,
    }
    relationships = (
        ("incident_alerts", "alerts_per_incident"),
        ("incident_evidence", "evidence_per_incident"),
        ("iocs", "iocs_per_incident"),
        ("response_actions", "response_actions_per_incident"),
    )
    for table, key in relationships:
        if incidents and table_exists(connection, table):
            result[key] = average_query(connection, f"""SELECT AVG(item_count) FROM (
              SELECT i.id, COUNT(t.rowid) item_count FROM incidents i
              LEFT JOIN {table} t ON t.incident_id = i.id GROUP BY i.id)""")
    return result


def response_metrics(connection: sqlite3.Connection) -> dict[str, Any]:
    by_status = grouped_counts(connection, "response_actions", "status")
    containment = 0
    if table_exists(connection, "response_actions"):
        containment = connection.execute("""SELECT COUNT(*) FROM response_actions
          WHERE action_type IN ('ISOLATE_HOST','DISABLE_ACCOUNT','BLOCK_INDICATOR','TERMINATE_PROCESS')""").fetchone()[0]
    return {
        "total_actions": count(connection, "response_actions"),
        "actions_by_status": by_status,
        "containment_actions": int(containment),
    }


def provenance_metrics(connection: sqlite3.Connection) -> dict[str, Any]:
    alerts = count(connection, "alerts")
    traced_alerts = 0
    if alerts and table_exists(connection, "events"):
        traced_alerts = connection.execute("""SELECT COUNT(*) FROM alerts a JOIN events e ON e.id=a.event_id
          WHERE e.source_file <> '' AND e.dataset <> '' AND e.raw_xml <> ''""").fetchone()[0]
    evidence = count(connection, "incident_evidence")
    referenced_evidence = 0
    if evidence and table_exists(connection, "events"):
        referenced_evidence = connection.execute("""SELECT COUNT(*) FROM incident_evidence ie
          JOIN events e ON e.id=ie.event_id JOIN alerts a ON a.id=ie.alert_id""").fetchone()[0]
    events = count(connection, "events")
    sourced_events = 0
    if events:
        sourced_events = connection.execute("""SELECT COUNT(*) FROM events
          WHERE source_file <> '' AND dataset <> '' AND raw_xml <> ''""").fetchone()[0]
    actions = count(connection, "response_actions")
    linked_actions = 0
    if actions and table_exists(connection, "action_evidence"):
        linked_actions = connection.execute("""SELECT COUNT(DISTINCT r.id) FROM response_actions r
          JOIN action_evidence ae ON ae.action_id=r.id""").fetchone()[0]
    return {
        "alerts": {"applicable": alerts, "traceable": int(traced_alerts),
                   "percent": percentage(traced_alerts, alerts)},
        "incident_evidence": {"applicable": evidence, "event_referenced": int(referenced_evidence),
                              "percent": percentage(referenced_evidence, evidence)},
        "events": {"applicable": events, "source_referenced": int(sourced_events),
                   "percent": percentage(sourced_events, events)},
        "response_actions": {"applicable": actions, "evidence_linked": int(linked_actions),
                             "percent": percentage(linked_actions, actions)},
    }
