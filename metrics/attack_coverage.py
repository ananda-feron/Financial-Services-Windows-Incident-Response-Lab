"""ATT&CK coverage across labeled telemetry, rules, and alert results."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from detection_engine.loader import load_rules
from metrics.database import percentage, table_exists
from metrics.detection_metrics import load_ground_truth


def attack_coverage(connection: sqlite3.Connection, rules_directory: Path,
                    manifest_path: Path) -> dict[str, Any]:
    manifest = load_ground_truth(manifest_path)
    observed = {sample["technique_id"] for sample in manifest["samples"]}
    rules = {rule.mitre.technique_id: rule for rule in load_rules(rules_directory) if rule.enabled}
    detected: set[str] = set()
    if table_exists(connection, "alerts"):
        detected = {row[0] for row in connection.execute(
            "SELECT DISTINCT technique_id FROM alerts WHERE technique_id IS NOT NULL"
        )}
    technique_ids = sorted(observed | rules.keys() | detected)
    rows = [{
        "technique_id": technique_id,
        "technique_name": rules[technique_id].mitre.technique_name if technique_id in rules else None,
        "observed_in_labeled_telemetry": technique_id in observed,
        "enabled_rule_exists": technique_id in rules,
        "detected": technique_id in detected,
    } for technique_id in technique_ids]
    covered = sum(row["enabled_rule_exists"] and row["detected"] for row in rows if row["observed_in_labeled_telemetry"])
    return {
        "observed_techniques": len(observed),
        "covered_observed_techniques": covered,
        "coverage_percent": percentage(covered, len(observed)),
        "techniques": rows,
        "observation_basis": "detection ground-truth manifest",
    }
