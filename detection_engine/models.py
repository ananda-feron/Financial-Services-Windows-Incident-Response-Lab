"""Validated in-memory models for detection rules and alerts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

SEVERITIES = {"low", "medium", "high", "critical"}
CONFIDENCES = {"low", "medium", "high"}
STATUSES = {"new", "triaged", "closed"}


@dataclass(frozen=True)
class AttackMapping:
    technique_id: str
    technique_name: str
    tactic: str
    curated_by: str
    curated_at: str
    mapping_rationale: str


@dataclass(frozen=True)
class DetectionRule:
    id: str
    version: str
    name: str
    description: str
    severity: str
    confidence: str
    conditions: dict[str, Any]
    mitre: AttackMapping
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.id.startswith("DET-"):
            raise ValueError("rule id must start with DET-")
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"invalid confidence: {self.confidence}")
        if not self.version:
            raise ValueError("rule version is required")


@dataclass(frozen=True)
class Alert:
    alert_id: str
    detection_id: str
    rule_version: str
    event_id: int
    event_key: str
    name: str
    severity: str
    confidence: str
    technique_id: str
    technique_name: str
    tactic: str
    status: str
    created_at: str
    source_file: str
    dataset: str
    curated_by: str
    curated_at: str
    mapping_rationale: str
    event_curated_mapping: dict[str, Any]
    upstream_mappings: list[dict[str, Any]]

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"invalid alert status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
