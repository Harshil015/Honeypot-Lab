"""Structured JSON logging and MITRE ATT&CK mapping."""

import logging
import json
from datetime import datetime, timezone
from flask import request, g
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
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def log_event(logger: logging.Logger, event_type: str, severity: str, mitre_id: str, mitre_tactic: str, payload: str = "", details: dict = None) -> dict:
    """Logs event, extracts IOCs, checks ML, and triggers SIEM alert."""
    
    src_ip = get_client_ip()
    
    # Feature 2: Extract IOCs
    iocs = extract_iocs(payload)
    # Feature 5: ML Anomaly Detection
    is_anomalous = detect_anomaly(src_ip)
    
    event_data = {
        "node_id": Config.NODE_ID, # Feature 4: Multi-Node ID
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "user_agent": request.headers.get("User-Agent", ""),
        "path": request.path,
        "method": request.method,
        "payload": payload,
        "mitre_technique_id": mitre_id,
        "mitre_tactic": mitre_tactic,
        "details": details or {},
        "iocs": iocs,
        "ml_anomaly": is_anomalous
    }
    
    logger.info(event_type, extra={"event_data": event_data})

    # Feature 1: Real-time SIEM Alerting for High/Critical events
    if severity in ["HIGH", "CRITICAL"] or is_anomalous:
        send_siem_alert(event_data)

    return event_data
