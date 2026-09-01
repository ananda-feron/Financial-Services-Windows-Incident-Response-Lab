# Event Log Analysis Notes

## Data dictionary

The lab uses portable JSON Lines. Each record includes common fields plus source detail.

| Field | Meaning |
|---|---|
| `timestamp` | ISO 8601 with timezone; parser normalizes UTC |
| `channel`, `event_id` | Windows source and identifier |
| `host`, `user` | Asset and subject identity |
| `source_ip`, `logon_type` | Authentication context |
| `image`, `parent_image`, `command_line` | Process-create context |

## Interpretation

- 4625: attempted-logon audit failure; real analysis needs status/substatus, package, workstation, source, and type.
- 4624: successful logon; type 10 is RemoteInteractive. Original logon ID should anchor correlation.
- 4672: sensitive privileges assigned. Common for privileged/service contexts and not proof of escalation.
- Sysmon 1: process creation with image, parent, user, hashes (if configured), and command line.

The detector combines user, host, source, and time window, then adds ancestry and command indicators. The benign `explorer.exe → powershell.exe Get-Date` event remains low severity, showing why context matters.

```bash
python3 detection/event_parser.py evidence/sample-events.jsonl
python3 detection/event_parser.py evidence/sample-events.jsonl --format json
```

Exit codes are `1` for high risk, `0` otherwise, and `2` for malformed/unreadable input, allowing simple CI use.
