"""Schema documentation for the SQLite-backed event store."""

EVENT_TABLE_SCHEMA = {
    "table": "events",
    "columns": [
        "id",
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
    ],
}
