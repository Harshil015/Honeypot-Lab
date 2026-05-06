"""SQLite persistence helpers for honeypot events."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from flask import current_app, g


EVENT_COLUMNS = (
    "timestamp",
    "event_type",
    "severity",
    "src_ip",
    "user_agent",
    "payload",
    "path",
    "method",
    "country",
    "city",
    "isp",
    "asn",
    "mitre_technique_id",
    "mitre_tactic",
    "details",
)


def get_db_connection() -> sqlite3.Connection:
    """Return the request-local SQLite connection."""
    if "db_connection" not in g:
        db_path = current_app.config["DATABASE_PATH"]
        g.db_connection = sqlite3.connect(db_path)
        g.db_connection.row_factory = sqlite3.Row
    return g.db_connection


def close_db_connection(_exception: BaseException | None = None) -> None:
    """Close the request-local SQLite connection, if one was opened."""
    connection = g.pop("db_connection", None)
    if connection is not None:
        connection.close()


def init_database(app) -> None:
    """Create the SQLite events table if it does not already exist."""
    db_path = Path(app.config["DATABASE_PATH"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                user_agent TEXT,
                payload TEXT,
                path TEXT,
                method TEXT,
                country TEXT,
                city TEXT,
                isp TEXT,
                asn TEXT,
                mitre_technique_id TEXT,
                mitre_tactic TEXT,
                details TEXT
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_country ON events(country)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_mitre ON events(mitre_technique_id)")


def save_event(event: dict[str, Any]) -> None:
    """Persist one structured event dictionary to SQLite."""
    row = dict(event)
    row["details"] = json.dumps(row.get("details") or {}, sort_keys=True)
    values = [row.get(column) for column in EVENT_COLUMNS]
    placeholders = ", ".join("?" for _ in EVENT_COLUMNS)
    columns = ", ".join(EVENT_COLUMNS)
    connection = get_db_connection()
    connection.execute(f"INSERT INTO events ({columns}) VALUES ({placeholders})", values)
    connection.commit()
