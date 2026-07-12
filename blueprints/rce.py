"""RCE emulation endpoint with full feature integration."""

from flask import Blueprint, request, g, current_app
from datetime import datetime, timezone
from extensions import save_event
from services.event_logger import log_event, get_client_ip
import logging

rce_bp = Blueprint("rce", __name__)

@rce_bp.route("/cmd", methods=["GET", "POST"])
def cmd_injection():
    payload = request.args.get("cmd") or request.form.get("cmd") or ""
    
    logger = logging.getLogger("honeypot.events")
    # This now handles IOC extraction, ML anomaly detection, and SIEM alerting internally
    event_data = log_event(logger, "RCE_ATTEMPT", "HIGH", "T1059", "Execution", payload=payload)
    
    save_event({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "node_id": current_app.config["NODE_ID"],
        "event_type": "RCE_ATTEMPT", "severity": "HIGH", "src_ip": get_client_ip(),
        "user_agent": request.headers.get("User-Agent", ""), "payload": payload, "path": request.path,
        "method": request.method, **g.geoip, "mitre_technique_id": "T1059", "mitre_tactic": "Execution", "details": {}
    })

    # Safe Emulation
    if "whoami" in payload: return "root", 200
    elif "id" in payload: return "uid=0(root) gid=0(root) groups=0(root)", 200
    elif "ls" in payload: return "index.html\nconfig.php\n.env", 200
    elif "uname" in payload: return "Linux webserver 5.4.0 #1 SMP x86_64 GNU/Linux", 200
    else: return f"bash: {payload.split(' ')[0]}: command not found", 200
