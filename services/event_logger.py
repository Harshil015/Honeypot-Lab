"""Structured JSON logging and MITRE ATT&CK mapping."""

import logging
import json
import threading
from datetime import datetime, timezone
from flask import request, current_app
from services.ioc_extractor import extract_iocs
from services.anomaly_detector import detect_anomaly
from services.siem_alerting import send_siem_alert
from config import Config

class JSONEventFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            **getattr(record, "event_data", {})
        }
        return json.dumps(log_entry, sort_keys=True)

def get_client_ip() -> str:
    """Return the real connecting IP.

    issue A1: X-Forwarded-For used to be trusted unconditionally, so any
    client could set it and have their spoofed IP logged as src_ip -- the
    field everything downstream (GeoIP, IOCs, SIEM alerts, session replay)
    keys off of. It's now only honored when the immediate TCP peer
    (request.remote_addr) is a known reverse proxy, per TRUSTED_PROXY_IPS.
    """
    remote_addr = request.remote_addr or "0.0.0.0"
    trusted_proxies = current_app.config.get("TRUSTED_PROXY_IPS") or frozenset()
    if remote_addr in trusted_proxies:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return remote_addr

def _dispatch_siem_alert_async(event_data: dict) -> None:
    """Send the SIEM webhook off the request/response path.

    issues E2/E3: this used to call send_siem_alert() synchronously inside
    log_event(), so a slow/unreachable SIEM could add up to its own
    request timeout of latency to what the attacker sees -- stacked on top
    of the (now also offloaded, see services/geoip.py) GeoIP lookup, that
    was a honeypot-fingerprinting signal. The real Flask app object is
    captured up front because `current_app` only resolves inside an active
    app/request context, which a plain background thread doesn't have.
    """
    app_obj = current_app._get_current_object()

    def _worker():
        with app_obj.app_context():
            send_siem_alert(event_data)

    threading.Thread(target=_worker, daemon=True).start()

def log_event(logger: logging.Logger, event_type: str, severity: str, mitre_id: str, mitre_tactic: str, payload: str = "", details: dict = None) -> dict:
    """Logs event, extracts IOCs, checks the anomaly heuristic, and triggers a SIEM alert.

    Returns a dict with every field both the JSON log and the SQLite
    `events` table need, so callers can pass it straight to
    extensions.save_event() instead of rebuilding an equivalent dict by
    hand in each blueprint. Previously each blueprint built its own
    separate dict for save_event(), and several of them quietly omitted
    node_id, iocs, and ml_anomaly -- issues D2/D3.
    """
    src_ip = get_client_ip()

    # Feature 2: Extract IOCs
    iocs = extract_iocs(payload)
    # Feature 5: rate-based anomaly heuristic -- see services/anomaly_detector.py
    is_anomalous = detect_anomaly(src_ip)

    event_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "node_id": Config.NODE_ID, # Feature 4: Multi-Node ID
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "user_agent": request.headers.get("User-Agent", ""),
        "path": request.path,
        "method": request.method,
        "payload": payload,
        # issue E1: GeoIP used to be looked up synchronously here on every
        # request. It's now enriched offline (once per unique IP) by
        # monitor_honeypot.py during analysis -- "Pending" is filled in
        # from there.
        "country": "Pending",
        "city": "Pending",
        "isp": "Pending",
        "asn": "Pending",
        "mitre_technique_id": mitre_id,
        "mitre_tactic": mitre_tactic,
        "details": details or {},
        "iocs": iocs,
        "ml_anomaly": is_anomalous
    }
    
    logger.info(event_type, extra={"event_data": event_data})

    # Feature 1: Real-time SIEM Alerting for High/Critical events
    if severity in ["HIGH", "CRITICAL"] or is_anomalous:
        _dispatch_siem_alert_async(event_data)

    return event_data
