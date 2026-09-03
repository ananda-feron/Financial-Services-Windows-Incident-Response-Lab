"""Dataset registry and separately maintained ground-truth metadata."""

from __future__ import annotations

import json
from pathlib import Path

REQUIRED_DATASET_FIELDS = {"dataset_id", "dataset_name", "publisher", "collection_period", "stream",
                           "platform", "source_url", "license", "ground_truth_available"}


def load_dataset(path: Path, dataset_id: str) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    for dataset in payload.get("datasets", []):
        if dataset.get("dataset_id") == dataset_id:
            missing = REQUIRED_DATASET_FIELDS - dataset.keys()
            if missing:
                raise ValueError(f"dataset registry missing: {', '.join(sorted(missing))}")
            return dataset
    raise ValueError(f"unknown dataset: {dataset_id}")


def load_ground_truth(path: Path, dataset_id: str) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("dataset_id") != dataset_id:
        raise ValueError("ground truth does not match dataset")
    for field in ("attack_windows", "techniques", "source_references"):
        if not isinstance(payload.get(field), list):
            raise ValueError(f"ground truth requires {field} list")
    return payload
