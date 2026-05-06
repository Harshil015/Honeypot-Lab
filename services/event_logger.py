"""Structured JSON logging and database persistence for honeypot events."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from flask import g, has_request_context, request

from extensions import save_event
from services.geoip import enrich_ip


MITRE_MAP = {
    "RCE_ATTEMPT": ("T1059", "Execution"),
    "RCE_RESULT": ("T1059", "Execution"),
    "RCE_TIMEOUT": ("T1059", "Execution"),
    "RCE_ERROR": ("T1059", "Execution"),
    "LOGIN_ATTEMPT": ("T1110", "Credential Access"),
    "FILE_UPLOAD": ("T1105", "Command and Control"),
    "WEBSHELL_UPLOAD": ("T1105", "Command and Control"),
    "WEBSHELL_POST": ("T1059", "Execution"),
    "WEBSHELL_GET": ("T1059", "Execution"),
    "JNDI_ATTEMPT": ("T1203", "Execution"),
    "CGI_POST": ("T1059", "Execution"),
    "CGI_GET": ("T1595", "Reconnaissance"),
    "ADMIN_API_ATTEMPT": ("T1190", "Initial Access"),
    "FAKE_FILE_READ": ("T1083", "Discovery"),
    "SERVER_STATUS": ("T1592", "Reconnaissance"),
    "HEADERS_ECHO": ("T1595", "Reconnaissance"),
    "PHPMYADMIN_BAIT": ("T1190", "Initial Access"),
    "TOMCAT_MANAGER_BAIT": ("T1190", "Initial Access"),
}


class JSONEventFormatter(logging.Formatter):
    """Format event records as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "event", None)
        if isinstance(event, dict):
            return json.dumps(event, default=str, sort_keys=True)
        return json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": record.levelname,
                "severity": record.levelname,
                "message": record.getMessage(),
            },
            default=str,
            sort_keys=True,
        )


def get_client_ip() -> str:
    """Resolve the request source IP with basic proxy-header support."""
    if not has_request_context():
        return "unknown"
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def get_user_agent() -> str:
    if not has_request_context():
        return "unknown"
    return request.headers.get("User-Agent", "unknown")


def log_event(
    event_type: str,
    *,
    severity: str = "INFO",
    payload: str | None = None,
    src_ip: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Enrich, persist, and emit a structured honeypot event."""
    timestamp = datetime.now(timezone.utc)
    src_ip = src_ip or get_client_ip()
    user_agent = user_agent or get_user_agent()
    path = request.path if has_request_context() else None
    method = request.method if has_request_context() else None
    technique_id, tactic = MITRE_MAP.get(event_type, (None, None))
    geo = getattr(g, "geoip", None) if has_request_context() else None
    if geo is None:
        geo = enrich_ip(src_ip)

    event = {
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "user_agent": user_agent,
        "payload": payload,
        "path": path,
        "method": method,
        "country": geo.get("country"),
        "city": geo.get("city"),
        "isp": geo.get("isp"),
        "asn": geo.get("asn"),
        "mitre_technique_id": technique_id,
        "mitre_tactic": tactic,
        "details": details or {},
    }

    save_event(event)

    logging.getLogger("honeypot.events").log(
        getattr(logging, severity.upper(), logging.INFO),
        event_type,
        extra={"event": event},
    )
    return event
