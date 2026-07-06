"""Brute-force login capture."""

from flask import Blueprint, request, g
from datetime import datetime, timezone
from extensions import save_event
from services.event_logger import log_event, get_client_ip
import logging

login_bp = Blueprint("login", __name__)

@login_bp.route("/login", methods=["GET", "POST"])
def login():
    app = login_bp.app
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        payload = f"{username}:{password}"
        
        logger = logging.getLogger("honeypot.events")
        log_event(logger, "BRUTE_FORCE", "MEDIUM", "T1110", "Credential Access", payload=payload)
        
        save_event({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "BRUTE_FORCE", "severity": "MEDIUM", "src_ip": get_client_ip(),
            "user_agent": request.headers.get("User-Agent", ""), "payload": payload, "path": request.path,
            "method": request.method, **g.geoip, "mitre_technique_id": "T1110", "mitre_tactic": "Credential Access", "details": {}
        })
        return "Invalid credentials", 401
    return "<form method='post'>Username: <input name='username'><br>Password: <input name='password' type='password'><br><button>Login</button></form>", 200
