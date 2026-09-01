#!/usr/bin/env python3
"""Correlate synthetic Windows/Sysmon JSONL events into an incident summary."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

FAILURE_THRESHOLD = 3
FAILURE_WINDOW = timedelta(minutes=10)
SUCCESS_WINDOW = timedelta(minutes=15)
SUSPICIOUS_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "wscript.exe", "mshta.exe"}
SUSPICIOUS_PS_TOKENS = ("-enc", "-encodedcommand", "-nop", "-w hidden", "invoke-expression", "iex", "downloadstring", "invoke-webrequest", "bypass")


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    channel: str
    event_id: int
    host: str
    user: str
    source_ip: str = "-"
    logon_type: int | None = None
    image: str = ""
    parent_image: str = ""
    command_line: str = ""
    description: str = ""


@dataclass(frozen=True)
class Finding:
    timestamp: str
    severity: str
    rule: str
    host: str
    user: str
    evidence: str


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def normalize(raw: dict) -> Event:
    required = ("timestamp", "channel", "event_id", "host", "user")
    missing = [field for field in required if field not in raw]
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(missing)}")
    return Event(
        timestamp=parse_timestamp(str(raw["timestamp"])), channel=str(raw["channel"]),
        event_id=int(raw["event_id"]), host=str(raw["host"]), user=str(raw["user"]),
        source_ip=str(raw.get("source_ip", "-")),
        logon_type=int(raw["logon_type"]) if raw.get("logon_type") is not None else None,
        image=str(raw.get("image", "")), parent_image=str(raw.get("parent_image", "")),
        command_line=str(raw.get("command_line", "")), description=str(raw.get("description", "")),
    )


def load_events(path: Path) -> list[Event]:
    events: list[Event] = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                events.append(normalize(json.loads(line)))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{number}: {exc}") from exc
    return sorted(events, key=lambda event: event.timestamp)


def basename(value: str) -> str:
    return value.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def analyze(events: Iterable[Event]) -> list[Finding]:
    findings: list[Finding] = []
    failures: dict[tuple[str, str, str], list[Event]] = defaultdict(list)
    suspicious_successes: dict[tuple[str, str], Event] = {}
    for event in sorted(events, key=lambda item: item.timestamp):
        key = (event.host.lower(), event.user.lower(), event.source_ip)
        actor = (event.host.lower(), event.user.lower())
        if event.event_id == 4625:
            recent = [item for item in failures[key] if event.timestamp - item.timestamp <= FAILURE_WINDOW]
            recent.append(event)
            failures[key] = recent
            if len(recent) == FAILURE_THRESHOLD:
                findings.append(Finding(iso(recent[0].timestamp), "medium", "AUTH_FAILURE_BURST", event.host, event.user, f"{len(recent)} failed logons from {event.source_ip} in {int((event.timestamp - recent[0].timestamp).total_seconds())} seconds"))
        elif event.event_id == 4624:
            prior = failures.get(key, [])
            if len(prior) >= FAILURE_THRESHOLD and timedelta(0) <= event.timestamp - prior[-1].timestamp <= SUCCESS_WINDOW:
                suspicious_successes[actor] = event
                findings.append(Finding(iso(event.timestamp), "high", "AUTH_SUCCESS_AFTER_FAILURES", event.host, event.user, f"successful logon type {event.logon_type} from {event.source_ip} after {len(prior)} failures"))
        elif event.event_id == 4672 and actor in suspicious_successes:
            success = suspicious_successes[actor]
            if timedelta(0) <= event.timestamp - success.timestamp <= timedelta(minutes=5):
                findings.append(Finding(iso(event.timestamp), "high", "PRIVILEGED_LOGON_CHAIN", event.host, event.user, "special privileges assigned shortly after correlated suspicious logon"))
        elif event.event_id == 1 and basename(event.image) in {"powershell.exe", "pwsh.exe"}:
            parent, command = basename(event.parent_image), event.command_line.lower()
            indicators = [token for token in SUSPICIOUS_PS_TOKENS if token in command]
            severity = "high" if parent in SUSPICIOUS_PARENTS or indicators else "low"
            evidence = f"parent={parent or 'unknown'}" + (f"; indicators={','.join(indicators)}" if indicators else "")
            findings.append(Finding(iso(event.timestamp), severity, "POWERSHELL_PROCESS", event.host, event.user, evidence))
            discovery = []
            if any(token in command for token in ("get-localuser", "get-aduser", "whoami", "net user")):
                discovery.append("account")
            if any(token in command for token in ("get-process", "tasklist")):
                discovery.append("process")
            if discovery:
                findings.append(Finding(iso(event.timestamp), "medium", "DISCOVERY_COMMAND", event.host, event.user, f"PowerShell command contains {' and '.join(discovery)} discovery"))
    return findings


def risk(findings: Iterable[Finding]) -> str:
    severities = [item.severity for item in findings]
    if severities.count("high") >= 2:
        return "High"
    if "high" in severities or severities.count("medium") >= 2:
        return "Medium"
    return "Low"


def result(events: list[Event], findings: list[Finding]) -> dict:
    implicated = [item for item in findings if item.severity in {"medium", "high"}]
    return {"incident": "WBF-IR-2025-001", "host": implicated[0].host if implicated else None,
            "user": implicated[0].user if implicated else None,
            "first_suspicious_event": min((item.timestamp for item in implicated), default=None),
            "events_analyzed": len(events), "risk_level": risk(findings),
            "status": "Investigation Required" if implicated else "No correlated incident",
            "findings": [asdict(item) for item in findings]}


def markdown(summary: dict) -> str:
    lines = ["# Incident Summary", "", f"- Incident: {summary['incident']}", f"- Host: {summary['host'] or '-'}",
             f"- User: {summary['user'] or '-'}", f"- First suspicious event: {summary['first_suspicious_event'] or '-'}",
             f"- Events analyzed: {summary['events_analyzed']}", f"- Risk level: **{summary['risk_level']}**",
             f"- Status: **{summary['status']}**", "", "## Findings", ""]
    lines.extend(f"- [{item['severity'].upper()}] {item['timestamp']} `{item['rule']}` — {item['evidence']}" for item in summary["findings"])
    if not summary["findings"]:
        lines.append("No correlated findings.")
    return "\n".join(lines)


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON Lines event export")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", type=Path, help="write report to a file")
    args = parser.parse_args(argv)
    try:
        events = load_events(args.input)
        summary = result(events, analyze(events))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(summary, indent=2) if args.format == "json" else markdown(summary)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 1 if summary["risk_level"] == "High" else 0


if __name__ == "__main__":
    raise SystemExit(cli())
