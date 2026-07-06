"""JNDI / Log4Shell capture."""

from flask import Blueprint, request, g
from datetime import datetime, timezone
from extensions import save_event
from services.event_logger import log_event, get_client_ip
import logging

jndi_bp = Blueprint("jndi", __name__)

@jndi_bp.route("/jndi", methods=["GET", "POST"])
def jndi_lookup():
    app = jndi_bp.app
    # Log4Shell often comes in via User-Agent or headers
    payload = request.headers.get("User-Agent") + " " + request.args.get("payload", "")
    
    logger = logging.getLogger("honeypot.events")
    log_event(logger, "JNDI_INJECTION", "CRITICAL", "T1059", "Execution", payload=payload)
    
    save_event({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "JNDI_INJECTION", "severity": "CRITICAL", "src_ip": get_client_ip(),
        "user_agent": request.headers.get("User-Agent", ""), "payload": payload, "path": request.path,
        "method": request.method, **g.geoip, "mitre_technique_id": "T1059", "mitre_tactic": "Execution", "details": {}
    })
    
    return "OK", 200
