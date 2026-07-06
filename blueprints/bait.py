"""Botnet bait endpoints."""

from flask import Blueprint, request, g
from datetime import datetime, timezone
from extensions import save_event
from services.event_logger import log_event, get_client_ip
import logging

bait_bp = Blueprint("bait", __name__)

@bait_bp.route("/shell.php", methods=["GET", "POST"])
@bait_bp.route("/cmd.php", methods=["GET", "POST"])
@bait_bp.route("/cgi-bin/", methods=["GET", "POST"])
def bait_endpoints():
    app = bait_bp.app
    payload = str(request.args) + str(request.form)
    
    logger = logging.getLogger("honeypot.events")
    log_event(logger, "BAIT_HIT", "LOW", "T1190", "Initial Access", payload=payload)
    
    save_event({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "BAIT_HIT", "severity": "LOW", "src_ip": get_client_ip(),
        "user_agent": request.headers.get("User-Agent", ""), "payload": payload, "path": request.path,
        "method": request.method, **g.geoip, "mitre_technique_id": "T1190", "mitre_tactic": "Initial Access", "details": {}
    })
    return "Not Found", 404
