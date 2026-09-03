"""Incident, alert-correlation, timeline, and note models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
INCIDENT_STATUSES = {"NEW", "TRIAGING", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"}


@dataclass(frozen=True)
class CorrelationAlert:
    database_alert_id: int
    alert_id: str
    detection_id: str
    severity: str
    technique_id: str
    technique_name: str
    tactic: str
    event_id: int
    event_key: str
    timestamp: datetime
    hostname: str
    username: str | None
    source_file: str
    dataset: str


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    status: str
    created_at: str
    updated_at: str
    description: str
    hostname: str
    username: str | None
    first_seen: str
    last_seen: str
    alerts: list[CorrelationAlert] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in INCIDENT_STATUSES:
            raise ValueError(f"invalid incident status: {self.status}")
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"invalid incident severity: {self.severity}")


@dataclass(frozen=True)
class TimelineEntry:
    timestamp: str
    incident_id: str
    alert_id: str
    detection_id: str
    severity: str
    technique_id: str
    technique_name: str
    event_id: int
    windows_event_id: int
    hostname: str
    username: str | None
    source_file: str
    dataset: str


@dataclass(frozen=True)
class AnalystNote:
    id: int
    incident_id: str
    author: str
    body: str
    created_at: str


def highest_severity(severities: list[str]) -> str:
    if not severities:
        raise ValueError("cannot aggregate an empty severity list")
    unknown = set(severities) - SEVERITY_RANK.keys()
    if unknown:
        raise ValueError(f"invalid severities: {', '.join(sorted(unknown))}")
    return max(severities, key=SEVERITY_RANK.__getitem__)
