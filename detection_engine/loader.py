"""Load and validate YAML detection rules; evaluation belongs in engine.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from detection_engine.models import AttackMapping, DetectionRule

REQUIRED_RULE_FIELDS = {"id", "version", "name", "description", "severity", "confidence", "conditions", "mitre", "enabled"}
REQUIRED_MITRE_FIELDS = {"technique_id", "technique_name", "tactic", "curated_by", "curated_at", "mapping_rationale"}


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping")
    return value


def load_rule(path: Path) -> DetectionRule:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: invalid YAML: {exc}") from exc
    data = _require_mapping(payload, "rule")
    missing = REQUIRED_RULE_FIELDS - data.keys()
    if missing:
        raise ValueError(f"{path}: missing rule fields: {', '.join(sorted(missing))}")
    mitre_data = _require_mapping(data["mitre"], "mitre")
    mitre_missing = REQUIRED_MITRE_FIELDS - mitre_data.keys()
    if mitre_missing:
        raise ValueError(f"{path}: missing MITRE fields: {', '.join(sorted(mitre_missing))}")
    return DetectionRule(
        id=str(data["id"]), version=str(data["version"]), name=str(data["name"]),
        description=str(data["description"]), severity=str(data["severity"]).lower(),
        confidence=str(data["confidence"]).lower(), conditions=_require_mapping(data["conditions"], "conditions"),
        mitre=AttackMapping(**{field: str(mitre_data[field]) for field in REQUIRED_MITRE_FIELDS}),
        enabled=bool(data["enabled"]),
    )


def load_rules(directory: Path) -> list[DetectionRule]:
    rules = [load_rule(path) for path in sorted(directory.glob("*.yaml"))]
    identities = [(rule.id, rule.version) for rule in rules]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate detection id/version in rule directory")
    return rules
