"""Evaluate normalized events, create ATT&CK-mapped alerts, and persist matches."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from detection_engine.database import insert_alerts, reconcile_alerts
from detection_engine.loader import load_rules
from detection_engine.models import Alert, DetectionRule, utc_now

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "data" / "events.db"
DEFAULT_RULES = ROOT / "detection_engine" / "rules"


def field_value(event: Mapping[str, Any], dotted_field: str) -> Any:
    value: Any = event
    for part in dotted_field.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def _text(value: Any, case_sensitive: bool) -> str:
    rendered = str(value)
    return rendered if case_sensitive else rendered.casefold()


def evaluate_condition(event: Mapping[str, Any], condition: Mapping[str, Any]) -> bool:
    if "all" in condition:
        return all(evaluate_condition(event, item) for item in condition["all"])
    if "any" in condition:
        return any(evaluate_condition(event, item) for item in condition["any"])
    if "not" in condition:
        return not evaluate_condition(event, condition["not"])
    field = condition.get("field")
    operator = condition.get("operator")
    if not field or not operator:
        raise ValueError("leaf condition requires field and operator")
    actual = field_value(event, str(field))
    if operator == "exists":
        expected = bool(condition.get("value", True))
        return (actual is not None and actual != "") is expected
    if actual is None:
        return False
    case_sensitive = bool(condition.get("case_sensitive", False))
    if operator == "equals":
        expected = condition.get("value")
        if isinstance(actual, str) or isinstance(expected, str):
            return _text(actual, case_sensitive) == _text(expected, case_sensitive)
        return actual == expected
    if operator == "in":
        values = condition.get("values", [])
        return any(evaluate_condition(event, {"field": field, "operator": "equals", "value": value, "case_sensitive": case_sensitive}) for value in values)
    if operator == "contains":
        return _text(condition.get("value", ""), case_sensitive) in _text(actual, case_sensitive)
    if operator == "contains_any":
        rendered = _text(actual, case_sensitive)
        return any(_text(value, case_sensitive) in rendered for value in condition.get("values", []))
    if operator == "ends_with":
        return _text(actual, case_sensitive).endswith(_text(condition.get("value", ""), case_sensitive))
    raise ValueError(f"unsupported operator: {operator}")


def evaluate(event: Mapping[str, Any], rule: DetectionRule) -> bool:
    return rule.enabled and evaluate_condition(event, rule.conditions)


def create_alert(event: Mapping[str, Any], rule: DetectionRule, created_at: str | None = None) -> Alert:
    database_event_id = int(event["id"])
    event_key = str(event["event_key"])
    identity = f"{rule.id}|{rule.version}|{event_key}"
    alert_id = "ALERT-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
    upstream = event.get("upstream_techniques", [])
    if isinstance(upstream, str):
        upstream = json.loads(upstream)
    return Alert(
        alert_id=alert_id, detection_id=rule.id, rule_version=rule.version,
        event_id=database_event_id, event_key=event_key, name=rule.name,
        severity=rule.severity, confidence=rule.confidence,
        technique_id=rule.mitre.technique_id, technique_name=rule.mitre.technique_name,
        tactic=rule.mitre.tactic, status="new", created_at=created_at or utc_now(),
        source_file=str(event["source_file"]), dataset=str(event["dataset"]),
        curated_by=rule.mitre.curated_by, curated_at=rule.mitre.curated_at,
        mapping_rationale=rule.mitre.mapping_rationale,
        event_curated_mapping={
            "technique_id": event.get("curated_technique_id") or event.get("technique_id"),
            "technique_name": event.get("curated_technique_name") or event.get("technique_name"),
            "curated_by": event.get("curated_by"), "curated_at": event.get("curated_at"),
            "mapping_rationale": event.get("mapping_rationale"),
        }, upstream_mappings=list(upstream),
    )


def database_events(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    connection.row_factory = sqlite3.Row
    events = []
    for row in connection.execute("SELECT * FROM events ORDER BY id"):
        event = dict(row)
        event["event_data"] = json.loads(event.pop("event_data_json"))
        event["upstream_techniques"] = json.loads(event.pop("upstream_techniques_json"))
        events.append(event)
    return events


def run(database: Path, rules_directory: Path) -> tuple[list[Alert], tuple[int, int]]:
    rules = load_rules(rules_directory)
    connection = sqlite3.connect(database)
    try:
        alerts = [create_alert(event, rule) for event in database_events(connection) for rule in rules if evaluate(event, rule)]
        result = insert_alerts(connection, alerts)
        reconcile_alerts(connection, ((rule.id, rule.version) for rule in rules if rule.enabled),
                         (alert.alert_id for alert in alerts))
        return alerts, result
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--output", type=Path, help="optional JSON alert output")
    args = parser.parse_args(argv)
    if not args.database.is_file():
        parser.error(f"database not found: {args.database}; run ingestion first")
    alerts, (inserted, duplicates) = run(args.database, args.rules)
    payload = {"matches": len(alerts), "inserted": inserted, "duplicates": duplicates,
               "alerts": [alert.to_dict() for alert in alerts]}
    rendered = json.dumps(payload, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
