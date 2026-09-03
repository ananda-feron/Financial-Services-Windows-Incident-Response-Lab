"""Command-line reporting for deterministic lab metrics."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

from metrics.attack_coverage import attack_coverage
from metrics.detection_metrics import detection_metrics, detection_performance
from metrics.incident_metrics import incident_metrics, provenance_metrics, response_metrics

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "data" / "events.db"
DEFAULT_RULES = ROOT / "detection_engine" / "rules"
DEFAULT_GROUND_TRUTH = ROOT / "data" / "metadata" / "detection_ground_truth.json"


def collect(command: str, connection: sqlite3.Connection, rules: Path,
            ground_truth: Path) -> dict[str, Any]:
    reports = {
        "detection": lambda: {**detection_metrics(connection, rules),
                              "performance": detection_performance(connection, ground_truth)},
        "incidents": lambda: {**incident_metrics(connection), "response": response_metrics(connection),
                              "provenance": provenance_metrics(connection)},
        "coverage": lambda: attack_coverage(connection, rules, ground_truth),
    }
    if command == "all":
        return {name: builder() for name, builder in reports.items()}
    return reports[command]()


def render_text(command: str, report: dict[str, Any]) -> str:
    if command == "all":
        return "\n\n".join(render_text(name, value) for name, value in report.items())
    title = {"detection": "Detection Metrics", "incidents": "Incident Metrics",
             "coverage": "ATT&CK Coverage"}[command]
    lines = [title, "=" * len(title)]
    for key, value in report.items():
        lines.append(f"{key.replace('_', ' ').title()}: {json.dumps(value, sort_keys=True)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("detection", "incidents", "coverage", "all"))
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)
    if not args.database.is_file():
        parser.error(f"database not found: {args.database}")
    try:
        connection = sqlite3.connect(args.database)
        report = collect(args.command, connection, args.rules, args.ground_truth)
    except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
        parser.error(str(exc))
    finally:
        if "connection" in locals():
            connection.close()
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render_text(args.command, report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
