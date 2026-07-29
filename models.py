"""Schema documentation for the SQLite-backed event store.

issue F3: this column list used to be maintained by hand and had drifted
out of sync with the real table (missing node_id). It's now derived
directly from extensions.EVENT_COLUMNS -- the actual source of truth for
the table definition -- so it can't go stale again.
"""

from extensions import EVENT_COLUMNS

EVENT_TABLE_SCHEMA = {
    "table": "events",
    "columns": ["id", *EVENT_COLUMNS],
}
