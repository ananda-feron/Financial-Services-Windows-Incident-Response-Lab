"""Create, approve, and simulate evidence-backed response actions.

No function in this module connects to an endpoint, identity provider, firewall,
or other external system. SIMULATED records an exercise outcome only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from response.database import ensure_schema, get_action
from response.models import ACTION_TYPES, CONTAINMENT_ACTIONS, ResponseAction

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "data" / "events.db"

INCIDENT_TRANSITIONS = {
    "NEW": {"TRIAGING"},
    "TRIAGING": {"INVESTIGATING"},
    "INVESTIGATING": {"CONTAINED"},
    "CONTAINED": {"ERADICATION"},
    "ERADICATION": {"RECOVERY"},
    "RECOVERY": {"RESOLVED"},
    "RESOLVED": {"CLOSED"},
    "CLOSED": set(),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def deterministic_action_id(incident_id: str, action_type: str, target: str) -> str:
    identity = f"{incident_id}|{action_type}|{target.strip().casefold()}"
    return "ACT-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()


def transition_incident(connection: sqlite3.Connection, incident_id: str, new_status: str,
                        changed_at: str | None = None, *, action_id: str | None = None) -> None:
    row = connection.execute("SELECT id, status FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if row is None:
        raise ValueError(f"unknown incident: {incident_id}")
    current = row[1]
    if new_status not in INCIDENT_TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid incident transition: {current} -> {new_status}")
    if new_status == "CONTAINED":
        action = get_action(connection, action_id or "")
        if (action is None or action.incident_id != incident_id or action.status != "SIMULATED"
                or action.action_type not in CONTAINMENT_ACTIONS):
            raise ValueError("CONTAINED requires a simulated containment action for this incident")
    timestamp = changed_at or utc_now()
    connection.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
                       (new_status, timestamp, row[0]))
    connection.commit()


def create_action(connection: sqlite3.Connection, incident_id: str, action_type: str,
                  target: str, rationale: str, analyst: str,
                  evidence_alert_ids: Iterable[str], created_at: str | None = None) -> tuple[ResponseAction, bool]:
    """Create an idempotent PLANNED action linked to this incident's evidence."""
    ensure_schema(connection)
    action_type = action_type.strip().upper()
    target, rationale, analyst = target.strip(), rationale.strip(), analyst.strip()
    if action_type not in ACTION_TYPES:
        raise ValueError(f"invalid response action type: {action_type}")
    if not target:
        raise ValueError("response target is required")
    if not rationale:
        raise ValueError("analyst rationale is required")
    if not analyst:
        raise ValueError("analyst is required")
    incident = connection.execute("SELECT id FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if incident is None:
        raise ValueError(f"unknown incident: {incident_id}")
    requested = tuple(dict.fromkeys(item.strip() for item in evidence_alert_ids if item.strip()))
    if not requested:
        raise ValueError("at least one evidence alert is required")
    placeholders = ",".join("?" for _ in requested)
    evidence = connection.execute(f"""SELECT ie.incident_id, ie.event_id, ie.alert_id, a.alert_id
      FROM incident_evidence ie JOIN alerts a ON a.id = ie.alert_id
      WHERE ie.incident_id = ? AND a.alert_id IN ({placeholders})""",
      (incident[0], *requested)).fetchall()
    found = {row[3] for row in evidence}
    missing = sorted(set(requested) - found)
    if missing:
        raise ValueError(f"evidence is not linked to incident {incident_id}: {', '.join(missing)}")
    timestamp = created_at or utc_now()
    action_id = deterministic_action_id(incident_id, action_type, target)
    before = connection.total_changes
    connection.execute("""INSERT OR IGNORE INTO response_actions (
      action_id, incident_id, action_type, target, normalized_target, status,
      rationale, analyst, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'PLANNED', ?, ?, ?, ?)""",
    (action_id, incident[0], action_type, target, target.casefold(), rationale, analyst, timestamp, timestamp))
    created = connection.total_changes > before
    database_action_id = connection.execute(
        "SELECT id FROM response_actions WHERE action_id = ?", (action_id,)).fetchone()[0]
    for incident_db_id, event_id, alert_db_id, _ in evidence:
        connection.execute("INSERT OR IGNORE INTO action_evidence VALUES (?, ?, ?, ?, ?)",
                           (database_action_id, incident_db_id, event_id, alert_db_id, timestamp))
    connection.commit()
    return get_action(connection, action_id), created


def _change_action_status(connection: sqlite3.Connection, action_id: str, expected: str,
                          new_status: str, changed_at: str | None = None) -> ResponseAction:
    ensure_schema(connection)
    action = get_action(connection, action_id)
    if action is None:
        raise ValueError(f"unknown response action: {action_id}")
    if action.status != expected:
        raise ValueError(f"invalid response action transition: {action.status} -> {new_status}")
    timestamp = changed_at or utc_now()
    connection.execute("UPDATE response_actions SET status = ?, updated_at = ? WHERE action_id = ?",
                       (new_status, timestamp, action_id))
    connection.commit()
    return get_action(connection, action_id)


def approve_action(connection: sqlite3.Connection, action_id: str,
                   changed_at: str | None = None) -> ResponseAction:
    return _change_action_status(connection, action_id, "PLANNED", "APPROVED", changed_at)


def cancel_action(connection: sqlite3.Connection, action_id: str,
                  changed_at: str | None = None) -> ResponseAction:
    action = get_action(connection, action_id)
    if action is None:
        raise ValueError(f"unknown response action: {action_id}")
    if action.status not in {"PLANNED", "APPROVED"}:
        raise ValueError(f"invalid response action transition: {action.status} -> CANCELLED")
    return _change_action_status(connection, action_id, action.status, "CANCELLED", changed_at)


def simulate_action(connection: sqlite3.Connection, action_id: str,
                    changed_at: str | None = None) -> ResponseAction:
    """Record a simulation; containment actions may move INVESTIGATING to CONTAINED."""
    evidence_count = connection.execute("""SELECT COUNT(*) FROM action_evidence ae
      JOIN response_actions r ON r.id = ae.action_id WHERE r.action_id = ?""", (action_id,)).fetchone()[0]
    if not evidence_count:
        raise ValueError("response action has no linked evidence")
    action = _change_action_status(connection, action_id, "APPROVED", "SIMULATED", changed_at)
    incident_status = connection.execute(
        "SELECT status FROM incidents WHERE incident_id = ?", (action.incident_id,)).fetchone()[0]
    if action.action_type in CONTAINMENT_ACTIONS and incident_status == "INVESTIGATING":
        transition_incident(connection, action.incident_id, "CONTAINED", changed_at, action_id=action_id)
    return get_action(connection, action_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="create an evidence-backed planned action")
    plan.add_argument("incident_id")
    plan.add_argument("action_type", choices=sorted(ACTION_TYPES))
    plan.add_argument("target")
    plan.add_argument("--rationale", required=True)
    plan.add_argument("--analyst", required=True)
    plan.add_argument("--evidence-alert", action="append", required=True, dest="evidence")
    for name in ("approve", "simulate", "cancel"):
        command = commands.add_parser(name, help=f"{name} a response action")
        command.add_argument("action_id")
    transition = commands.add_parser("transition", help="advance an incident lifecycle state")
    transition.add_argument("incident_id")
    transition.add_argument("status", choices=sorted({item for values in INCIDENT_TRANSITIONS.values() for item in values}))
    transition.add_argument("--action-id", help="required when transitioning to CONTAINED")
    args = parser.parse_args(argv)
    if not args.database.is_file():
        parser.error("database not found; run ingestion, detection, and correlation first")
    connection = sqlite3.connect(args.database)
    try:
        if args.command == "plan":
            action, created = create_action(connection, args.incident_id, args.action_type,
                                            args.target, args.rationale, args.analyst, args.evidence)
            result = {**action.__dict__, "created": created}
        elif args.command == "approve":
            result = approve_action(connection, args.action_id).__dict__
        elif args.command == "simulate":
            result = simulate_action(connection, args.action_id).__dict__
        elif args.command == "cancel":
            result = cancel_action(connection, args.action_id).__dict__
        else:
            transition_incident(connection, args.incident_id, args.status, action_id=args.action_id)
            result = {"incident_id": args.incident_id, "status": args.status}
    except (ValueError, sqlite3.Error) as exc:
        parser.error(str(exc))
    finally:
        connection.close()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
