"""Models and controlled vocabularies for simulated response actions."""

from __future__ import annotations

from dataclasses import dataclass

ACTION_TYPES = {
    "ISOLATE_HOST",
    "DISABLE_ACCOUNT",
    "BLOCK_INDICATOR",
    "TERMINATE_PROCESS",
    "COLLECT_ARTIFACT",
}
ACTION_STATUSES = {"PLANNED", "APPROVED", "SIMULATED", "CANCELLED"}
CONTAINMENT_ACTIONS = {
    "ISOLATE_HOST",
    "DISABLE_ACCOUNT",
    "BLOCK_INDICATOR",
    "TERMINATE_PROCESS",
}


@dataclass(frozen=True)
class ResponseAction:
    action_id: str
    incident_id: str
    action_type: str
    target: str
    status: str
    rationale: str
    analyst: str
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        if self.action_type not in ACTION_TYPES:
            raise ValueError(f"invalid response action type: {self.action_type}")
        if self.status not in ACTION_STATUSES:
            raise ValueError(f"invalid response action status: {self.status}")
        if not self.target.strip():
            raise ValueError("response target is required")
        if not self.rationale.strip():
            raise ValueError("analyst rationale is required")
        if not self.analyst.strip():
            raise ValueError("analyst is required")
