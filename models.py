"""Schema documentation for the SQLite-backed event store.
"""

from extensions import EVENT_COLUMNS

EVENT_TABLE_SCHEMA = {
    "table": "events",
    "columns": ["id", *EVENT_COLUMNS],
}
