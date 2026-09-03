"""Deterministically correlate ATT&CK-mapped alerts into incidents."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from incidents.database import persist_incidents
from incidents.models import CorrelationAlert, Incident, highest_severity

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "data" / "events.db"
DEFAULT_WINDOW = timedelta(minutes=15)

RELATED_TACTICS = {
    frozenset(("Execution", "Credential Access")),
    frozenset(("Execution", "Persistence")),
    frozenset(("Execution", "Discovery")),
    frozenset(("Execution", "Lateral Movement")),
    frozenset(("Credential Access", "Lateral Movement")),
}


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_alerts(connection: sqlite3.Connection) -> list[CorrelationAlert]:
    rows = connection.execute("""SELECT
        a.id, a.alert_id, a.detection_id, a.severity, a.technique_id,
        a.technique_name, a.tactic, e.id, e.event_key, e.timestamp,
        e.hostname, e.username, e.source_file, e.dataset
      FROM alerts a JOIN events e ON e.id = a.event_id
      WHERE a.status <> 'stale'
      ORDER BY e.timestamp, a.alert_id""").fetchall()
    return [CorrelationAlert(
        database_alert_id=row[0], alert_id=row[1], detection_id=row[2], severity=row[3],
        technique_id=row[4], technique_name=row[5], tactic=row[6], event_id=row[7],
        event_key=row[8], timestamp=parse_timestamp(row[9]), hostname=row[10],
        username=row[11], source_file=row[12], dataset=row[13],
    ) for row in rows]


def related_activity(left: CorrelationAlert, right: CorrelationAlert) -> bool:
    return (left.technique_id == right.technique_id or left.tactic == right.tactic or
            frozenset((left.tactic, right.tactic)) in RELATED_TACTICS)


def same_identity(left: CorrelationAlert, right: CorrelationAlert) -> bool:
    """Missing users correlate only with other missing users, never a named identity."""
    left_user = left.username.casefold() if left.username else None
    right_user = right.username.casefold() if right.username else None
    return left.hostname.casefold() == right.hostname.casefold() and left_user == right_user


def belongs(alert: CorrelationAlert, cluster: list[CorrelationAlert], window: timedelta) -> bool:
    latest = cluster[-1]
    delta = alert.timestamp - latest.timestamp
    return timedelta(0) <= delta <= window and same_identity(alert, latest) and any(
        related_activity(alert, existing) for existing in cluster
    )


def incident_title(alerts: list[CorrelationAlert]) -> str:
    techniques = {alert.technique_id for alert in alerts}
    if any(technique.startswith("T1003") for technique in techniques):
        return "Suspected Credential Access Activity"
    if "T1047" in techniques:
        return "Suspicious WMI Execution"
    if "T1059.001" in techniques:
        return "Suspicious PowerShell Activity"
    return "Correlated Security Activity"


def build_incident(cluster: list[CorrelationAlert], recorded_at: str) -> Incident:
    first, last = cluster[0], cluster[-1]
    incident_id = "INC-" + hashlib.sha256(first.alert_id.encode("utf-8")).hexdigest()[:10].upper()
    technique_list = ", ".join(sorted({alert.technique_id for alert in cluster}))
    description = (f"Correlated {len(cluster)} alert(s) on {first.hostname} for "
                   f"{first.username or 'an unresolved user'} within the configured time window. "
                   f"Observed ATT&CK techniques: {technique_list}.")
    return Incident(
        incident_id=incident_id, title=incident_title(cluster),
        severity=highest_severity([alert.severity for alert in cluster]), status="NEW",
        created_at=recorded_at, updated_at=recorded_at, description=description,
        hostname=first.hostname, username=first.username,
        first_seen=first.timestamp.isoformat().replace("+00:00", "Z"),
        last_seen=last.timestamp.isoformat().replace("+00:00", "Z"), alerts=list(cluster),
    )


def correlate(alerts: Iterable[CorrelationAlert], window: timedelta = DEFAULT_WINDOW,
              recorded_at: str | None = None) -> list[Incident]:
    if window <= timedelta(0):
        raise ValueError("correlation window must be positive")
    timestamp = recorded_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    clusters: list[list[CorrelationAlert]] = []
    for alert in sorted(alerts, key=lambda item: (item.timestamp, item.alert_id)):
        candidates = [cluster for cluster in clusters if belongs(alert, cluster, window)]
        if candidates:
            most_recent = max(candidates, key=lambda cluster: cluster[-1].timestamp)
            most_recent.append(alert)
        else:
            clusters.append([alert])
    return [build_incident(cluster, timestamp) for cluster in clusters]


def run(database: Path, window: timedelta = DEFAULT_WINDOW) -> tuple[list[Incident], tuple[int, int, int]]:
    connection = sqlite3.connect(database)
    try:
        incidents = correlate(load_alerts(connection), window)
        return incidents, persist_incidents(connection, incidents)
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--window-minutes", type=int, default=15)
    parser.add_argument("--render-dir", type=Path, help="write one static investigation page per incident")
    args = parser.parse_args(argv)
    if args.window_minutes < 1:
        parser.error("--window-minutes must be positive")
    if not args.database.is_file():
        parser.error("database not found; run ingestion and detection first")
    try:
        incidents, persisted = run(args.database, timedelta(minutes=args.window_minutes))
    except sqlite3.OperationalError as exc:
        parser.error(f"database is not ready for correlation: {exc}")
    rendered = []
    if args.render_dir:
        from incidents.view import render_incident_page
        args.render_dir.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(args.database)
        try:
            for incident in incidents:
                output = args.render_dir / f"{incident.incident_id}.html"
                render_incident_page(connection, incident.incident_id, output)
                rendered.append(str(output))
        finally:
            connection.close()
    print(json.dumps({
        "alerts_correlated": sum(len(incident.alerts) for incident in incidents),
        "incidents": [{"incident_id": item.incident_id, "title": item.title,
                       "severity": item.severity, "status": item.status,
                       "hostname": item.hostname, "username": item.username,
                       "alert_count": len(item.alerts), "first_seen": item.first_seen,
                       "last_seen": item.last_seen} for item in incidents],
        "persistence": {"incidents_upserted": persisted[0], "alert_links_inserted": persisted[1],
                        "evidence_links_inserted": persisted[2]},
        "rendered_pages": rendered,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
