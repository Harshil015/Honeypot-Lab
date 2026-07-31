"""SQLite persistence helpers for honeypot events."""

from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from typing import Any
from flask import current_app, g

EVENT_COLUMNS = (
    "timestamp", "node_id", "event_type", "severity", "src_ip", "user_agent", "payload",
    "path", "method", "country", "city", "isp", "asn",
    "mitre_technique_id", "mitre_tactic", "details", "iocs", "ml_anomaly"
)

def get_db_connection() -> sqlite3.Connection:
    if "db_connection" not in g:
        g.db_connection = sqlite3.connect(current_app.config["DATABASE_PATH"])
        g.db_connection.row_factory = sqlite3.Row
    return g.db_connection

def close_db_connection(_exception: BaseException | None = None) -> None:
    connection = g.pop("db_connection", None)
    if connection is not None:
        connection.close()

def _ensure_schema_migrations(conn: sqlite3.Connection) -> None:
    """Add columns that didn't exist in earlier versions of this schema to
    an already-created events.db, so upgrading doesn't require deleting
    existing captured data. CREATE TABLE IF NOT EXISTS alone is a no-op
    against a pre-existing table, even if its columns differ.
    """
    existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    for col, col_type in (("node_id", "TEXT"), ("iocs", "TEXT"), ("ml_anomaly", "INTEGER")):
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")

def init_database(app) -> None:
    db_path = Path(app.config["DATABASE_PATH"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL, node_id TEXT, event_type TEXT NOT NULL, severity TEXT NOT NULL,
                src_ip TEXT NOT NULL, user_agent TEXT, payload TEXT, path TEXT, method TEXT,
                country TEXT, city TEXT, isp TEXT, asn TEXT,
                mitre_technique_id TEXT, mitre_tactic TEXT, details TEXT,
                iocs TEXT, ml_anomaly INTEGER
            )
        """)
        _ensure_schema_migrations(conn)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_node ON events(node_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")

def save_event(event: dict[str, Any]) -> None:
    row = dict(event)
    row["details"] = json.dumps(row.get("details") or {}, sort_keys=True)
    row["iocs"] = json.dumps(row.get("iocs") or {}, sort_keys=True)
    values = [row.get(col) for col in EVENT_COLUMNS]
    placeholders = ", ".join("?" for _ in EVENT_COLUMNS)
    columns = ", ".join(EVENT_COLUMNS)
    
    connection = get_db_connection()
    connection.execute(f"INSERT INTO events ({columns}) VALUES ({placeholders})", values)
    connection.commit()
