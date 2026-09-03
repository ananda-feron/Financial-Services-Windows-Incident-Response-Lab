"""Detection counts and labeled positive-test effectiveness."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from detection_engine.loader import load_rules
from metrics.database import count, grouped_counts, table_exists


def detection_metrics(connection: sqlite3.Connection, rules_directory: Path) -> dict[str, Any]:
    rules = [rule for rule in load_rules(rules_directory) if rule.enabled]
    events = count(connection, "events")
    alerts = int(connection.execute("SELECT COUNT(*) FROM alerts WHERE status <> 'stale'").fetchone()[0]) if table_exists(connection, "alerts") else 0
    return {
        "events_analyzed": events,
        "enabled_rules": len(rules),
        "rules_evaluated": events * len(rules),
        "alerts_generated": alerts,
        "alerts_by_severity": dict(connection.execute("SELECT severity,COUNT(*) FROM alerts WHERE status <> 'stale' GROUP BY severity ORDER BY severity").fetchall()) if table_exists(connection, "alerts") else {},
        "alerts_by_detection": dict(connection.execute("SELECT detection_id,COUNT(*) FROM alerts WHERE status <> 'stale' GROUP BY detection_id ORDER BY detection_id").fetchall()) if table_exists(connection, "alerts") else {},
    }


def load_ground_truth(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("samples"), list):
        raise ValueError("ground-truth manifest requires a samples list")
    for sample in data["samples"]:
        if not sample.get("source_file") or not sample.get("technique_id"):
            raise ValueError("ground-truth sample requires source_file and technique_id")
        if not isinstance(sample.get("expected_detections"), list):
            raise ValueError("ground-truth sample requires expected_detections")
    return data


def detection_performance(connection: sqlite3.Connection, manifest_path: Path) -> dict[str, Any]:
    manifest = load_ground_truth(manifest_path)
    expected = {
        (sample["source_file"], detection_id)
        for sample in manifest["samples"]
        for detection_id in sample["expected_detections"]
    }
    actual: set[tuple[str, str]] = set()
    if table_exists(connection, "alerts") and table_exists(connection, "events"):
        actual = {
            (str(row[0]), str(row[1]))
            for row in connection.execute("""SELECT DISTINCT e.source_file, a.detection_id
              FROM alerts a JOIN events e ON e.id = a.event_id WHERE a.status <> 'stale'""")
        }
    render = lambda pairs: [
        {"source_file": source, "detection_id": detection}
        for source, detection in sorted(pairs)
    ]
    return {
        "expected_detections": len(expected),
        "actual_detection_outcomes": len(actual),
        "matched_detections": len(expected & actual),
        "missed_detections": render(expected - actual),
        "unexpected_detections": render(actual - expected),
        "scope": "labeled positive sample/rule outcomes",
        "precision": None,
        "recall": round(len(expected & actual) / len(expected), 4) if expected else None,
        "f1": None,
        "false_positive_rate": None,
    }
