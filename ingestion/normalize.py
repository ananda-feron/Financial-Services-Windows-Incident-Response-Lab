"""Normalize Windows Event XML without discarding the original XML."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Mapping


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first(element: ET.Element, name: str) -> ET.Element | None:
    return next((item for item in element.iter() if _local_name(item.tag) == name), None)


def _text(element: ET.Element, name: str) -> str | None:
    item = _first(element, name)
    return item.text.strip() if item is not None and item.text and item.text.strip() else None


def event_values(root: ET.Element) -> dict[str, str]:
    """Flatten named EventData plus leaf UserData values."""
    values: dict[str, str] = {}
    for item in root.iter():
        local = _local_name(item.tag)
        text = item.text.strip() if item.text and item.text.strip() else None
        if local == "Data" and text:
            name = item.attrib.get("Name")
            if name:
                values[name] = text
        elif text and len(item) == 0 and local not in {
            "EventID", "EventRecordID", "Computer", "Channel", "Version", "Level",
            "Task", "Opcode", "Keywords", "Correlation", "Security",
        }:
            values.setdefault(local, text)
    return values


def _pick(values: Mapping[str, str], *names: str) -> str | None:
    return next((values[name] for name in names if values.get(name)), None)


def normalize_event(xml: str, metadata: Mapping[str, Any], record_index: int) -> dict[str, Any]:
    """Convert one EVTX XML record into the stable application schema."""
    root = ET.fromstring(xml)
    system = _first(root, "System")
    if system is None:
        raise ValueError("event XML has no System element")
    event_id_text = _text(system, "EventID")
    if not event_id_text:
        raise ValueError("event XML has no EventID")
    provider = _first(system, "Provider")
    created = _first(system, "TimeCreated")
    values = event_values(root)
    username = _pick(values, "User", "TargetUserName", "SubjectUserName", "AccountName")
    domain = _pick(values, "TargetDomainName", "SubjectDomainName")
    if username and domain and "\\" not in username and domain not in {"-", "."}:
        username = f"{domain}\\{username}"

    return {
        "timestamp": created.attrib.get("SystemTime") if created is not None else None,
        "event_id": int(event_id_text),
        "event_record_id": _text(system, "EventRecordID"),
        "computer": _text(system, "Computer"),
        "username": username,
        "process_name": _pick(values, "Image", "NewProcessName", "Application", "ProcessName"),
        "parent_process": _pick(values, "ParentImage", "ParentProcessName", "CreatorProcessName"),
        "command_line": _pick(values, "CommandLine", "ProcessCommandLine", "ParentCommandLine", "ScriptBlockText"),
        "source_ip": _pick(values, "SourceIp", "IpAddress", "SourceAddress", "ClientIP"),
        "source": _text(system, "Channel"),
        "provider": provider.attrib.get("Name") if provider is not None else None,
        "dataset": metadata.get("dataset", "EVTX-ATTACK-SAMPLES"),
        "source_file": metadata.get("source_file"),
        "source_category": metadata.get("source_category"),
        "attack_technique": metadata.get("technique_id"),
        "attack_technique_name": metadata.get("technique_name"),
        "attack_tactic": metadata.get("attack_tactic"),
        "curated_technique_id": metadata.get("technique_id"),
        "curated_technique_name": metadata.get("technique_name"),
        "curated_by": metadata.get("curated_by"),
        "curated_at": metadata.get("curated_at"),
        "mapping_rationale": metadata.get("mapping_basis"),
        "upstream_techniques": metadata.get("upstream_techniques", []),
        "record_index": record_index,
        "event_data": values,
        "raw_xml": xml,
    }
