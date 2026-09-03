"""Add an analyst note to an existing incident."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from incidents.database import add_note

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("incident_id")
    parser.add_argument("--author", default="Project analyst")
    parser.add_argument("--body", required=True)
    parser.add_argument("--database", type=Path, default=ROOT / "data/events.db")
    args = parser.parse_args(argv)
    connection = sqlite3.connect(args.database)
    try:
        note = add_note(connection, args.incident_id, args.author, args.body)
    except ValueError as exc:
        parser.error(str(exc))
    finally:
        connection.close()
    print(json.dumps({"id": note.id, "incident_id": note.incident_id,
                      "author": note.author, "body": note.body,
                      "created_at": note.created_at}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
