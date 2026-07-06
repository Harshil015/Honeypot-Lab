"""Structured JSON logging and MITRE ATT&CK mapping."""

import logging
import json
from datetime import datetime, timezone
from flask import request

class JSONEventFormatter(logging.Formatter):
    """Formats log records as JSON lines."""
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            **getattr(record, "event_data", {})
        }
        return json.dumps(log_entry, sort_keys=True)

def get_client_ip() -> str:
    """Safely extract client IP, handling reverse proxies."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def log_event(logger: logging.Logger, event_type: str, severity: str, mitre_id: str, mitre_tactic: str, payload: str = "", details: dict = None) -> None:
    """Log a structured honeypot event."""
    event_data = {
        "event_type": event_type,
        "severity": severity,
        "src_ip": get_client_ip(),
        "user_agent": request.headers.get("User-Agent", ""),
        "path": request.path,
        "method": request.method,
        "payload": payload,
        "mitre_technique_id": mitre_id,
        "mitre_tactic": mitre_tactic,
        "details": details or {}
    }
    logger.info(event_type, extra={"event_data": event_data})
