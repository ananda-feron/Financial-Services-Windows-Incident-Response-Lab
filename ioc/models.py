"""Models for extracted incident indicators and their event provenance."""

from __future__ import annotations

from dataclasses import dataclass

IOC_TYPES = {"ip", "hostname", "username", "process", "command_line", "file_path", "hash", "domain"}


@dataclass(frozen=True)
class IOCObservation:
    incident_id: str
    event_id: int
    ioc_type: str
    value: str
    normalized_value: str
    source: str
    first_seen: str | None

    def __post_init__(self) -> None:
        if self.ioc_type not in IOC_TYPES:
            raise ValueError(f"unsupported IOC type: {self.ioc_type}")
        if not self.value.strip() or not self.normalized_value.strip():
            raise ValueError("IOC value cannot be empty")


@dataclass(frozen=True)
class IOC:
    ioc_id: str
    incident_id: str
    event_id: int
    ioc_type: str
    value: str
    source: str
    first_seen: str | None
