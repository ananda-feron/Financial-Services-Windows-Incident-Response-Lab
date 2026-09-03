"""Extract incident-linked observables from existing normalized event records."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Mapping

from ioc.database import persist_observations
from ioc.models import IOCObservation

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "data/events.db"
IP_FIELDS = ("source_ip", "SourceIp", "DestinationIp", "IpAddress", "SourceAddress", "DestAddress", "ClientIP")
HOST_FIELDS = ("hostname", "SourceHostname", "DestinationHostname", "WorkstationName", "Workstation", "TargetServerName")
USER_FIELDS = ("username", "User", "TargetUserName", "SubjectUserName", "AccountName")
PROCESS_FIELDS = ("process_name", "parent_process", "Image", "SourceImage", "TargetImage", "NewProcessName", "ParentImage")
COMMAND_FIELDS = ("command_line", "CommandLine", "ParentCommandLine", "ScriptBlockText")
PATH_FIELDS = ("process_name", "parent_process", "Image", "SourceImage", "TargetImage", "NewProcessName", "ParentImage", "TargetFilename", "Path", "ImageLoaded")
HASH_PATTERN = re.compile(r"\b(MD5|SHA1|SHA256|IMPHASH)=([A-Fa-f0-9]{16,64})\b")
URL_DOMAIN_PATTERN = re.compile(r"https?://((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})(?=[:/]|$)", re.I)
DOMAIN_FIELDS = ("DestinationHostname", "SourceHostname", "TargetServerName", "DnsHostName")
PATH_PATTERN = re.compile(r"^[A-Za-z]:\\")


def _basename(value: str) -> str:
    return value.replace("/", "\\").rsplit("\\", 1)[-1]


def _normalize(ioc_type: str, value: str) -> str:
    cleaned = " ".join(value.strip().split()) if ioc_type == "command_line" else value.strip()
    if ioc_type == "ip":
        return str(ipaddress.ip_address(cleaned))
    if ioc_type in {"hostname", "username", "process", "file_path", "hash", "domain"}:
        return cleaned.casefold()
    return cleaned


def _add(output: list[tuple[str, str, str]], ioc_type: str, value: Any, source: str) -> None:
    if value is None or not str(value).strip() or str(value).strip() in {"-", "::", "0.0.0.0"}:
        return
    rendered = str(value).strip()
    try:
        normalized = _normalize(ioc_type, rendered)
    except ValueError:
        return
    output.append((ioc_type, rendered, f"{source}|{normalized}"))


def extract_values(event: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """Return `(type, display value, source|normalized value)` tuples."""
    data = event.get("event_data") or {}
    candidates: dict[str, Any] = {**data, **{key: event.get(key) for key in (
        "hostname", "username", "process_name", "parent_process", "command_line", "source_ip"
    )}}
    output: list[tuple[str, str, str]] = []
    for field in IP_FIELDS:
        value = candidates.get(field)
        if value:
            for token in re.split(r"[,;\s]+", str(value)):
                _add(output, "ip", token, field)
    for field in HOST_FIELDS:
        _add(output, "hostname", candidates.get(field), field)
    for field in USER_FIELDS:
        _add(output, "username", candidates.get(field), field)
    for field in PROCESS_FIELDS:
        value = candidates.get(field)
        if value:
            _add(output, "process", _basename(str(value)), field)
    for field in COMMAND_FIELDS:
        _add(output, "command_line", candidates.get(field), field)
    for field in PATH_FIELDS:
        value = candidates.get(field)
        if value and PATH_PATTERN.match(str(value).strip()):
            _add(output, "file_path", value, field)
    for field, value in data.items():
        if value and (field == "Hashes" or "hash" in field.casefold()):
            for algorithm, digest in HASH_PATTERN.findall(str(value)):
                _add(output, "hash", f"{algorithm.lower()}:{digest.lower()}", field)
    for field in DOMAIN_FIELDS:
        value = candidates.get(field)
        if value and "." in str(value):
            _add(output, "domain", str(value).rstrip("."), field)
    for field in COMMAND_FIELDS:
        value = candidates.get(field)
        if value:
            for domain in URL_DOMAIN_PATTERN.findall(str(value)):
                _add(output, "domain", domain.rstrip("."), field)

    unique: dict[tuple[str, str], tuple[str, str, str]] = {}
    for ioc_type, value, packed in output:
        source, normalized = packed.split("|", 1)
        unique.setdefault((ioc_type, normalized), (ioc_type, value, source))
    return list(unique.values())


def incident_events(connection: sqlite3.Connection, incident_id: str) -> list[dict[str, Any]]:
    connection.row_factory = sqlite3.Row
    rows = connection.execute("""SELECT DISTINCT e.id, e.timestamp, e.hostname, e.username,
      e.process_name, e.parent_process, e.command_line, e.source_ip, e.event_data_json
      FROM incident_evidence ie JOIN incidents i ON i.id = ie.incident_id
      JOIN events e ON e.id = ie.event_id WHERE i.incident_id = ? ORDER BY e.timestamp, e.id""",
      (incident_id,)).fetchall()
    events = []
    for row in rows:
        event = dict(row)
        event["event_data"] = json.loads(event.pop("event_data_json"))
        events.append(event)
    return events


def extract_incident(connection: sqlite3.Connection, incident_id: str) -> list[IOCObservation]:
    observations: list[IOCObservation] = []
    for event in incident_events(connection, incident_id):
        for ioc_type, value, source_field in extract_values(event):
            observations.append(IOCObservation(
                incident_id=incident_id, event_id=event["id"], ioc_type=ioc_type,
                value=value, normalized_value=_normalize(ioc_type, value),
                source=f"event:{event['id']}:{source_field}", first_seen=event["timestamp"],
            ))
    return observations


def incident_ids(connection: sqlite3.Connection) -> list[str]:
    return [row[0] for row in connection.execute("SELECT incident_id FROM incidents ORDER BY first_seen, incident_id")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--incident", action="append", help="incident ID; repeat to select multiple")
    args = parser.parse_args(argv)
    if not args.database.is_file():
        parser.error("database not found; run Phases 1–3 first")
    connection = sqlite3.connect(args.database)
    try:
        selected = args.incident or incident_ids(connection)
        summary = []
        for incident_id in selected:
            observations = extract_incident(connection, incident_id)
            inserted, duplicates, sightings = persist_observations(connection, observations)
            summary.append({"incident_id": incident_id, "observations": len(observations),
                            "new_iocs": inserted, "duplicate_iocs": duplicates,
                            "new_sightings": sightings})
    except (sqlite3.OperationalError, ValueError) as exc:
        parser.error(str(exc))
    finally:
        connection.close()
    print(json.dumps({"incidents_processed": len(summary), "results": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
