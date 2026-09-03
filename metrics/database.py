"""Small SQLite helpers shared by metrics calculations."""

from __future__ import annotations

import sqlite3
from typing import Any


def table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def count(connection: sqlite3.Connection, table: str) -> int:
    if not table_exists(connection, table):
        return 0
    return int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])


def grouped_counts(connection: sqlite3.Connection, table: str, column: str) -> dict[str, int]:
    if not table_exists(connection, table):
        return {}
    rows = connection.execute(
        f'SELECT "{column}", COUNT(*) FROM "{table}" GROUP BY "{column}" ORDER BY "{column}"'
    ).fetchall()
    return {str(key): int(value) for key, value in rows}


def percentage(numerator: int, denominator: int) -> float | None:
    return round(100 * numerator / denominator, 2) if denominator else None


def average_query(connection: sqlite3.Connection, query: str) -> float | None:
    value: Any = connection.execute(query).fetchone()[0]
    return round(float(value), 2) if value is not None else None
