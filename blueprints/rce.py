"""RCE emulation endpoint."""

from flask import Blueprint, request
from services.event_logger import log_event
from extensions import save_event

rce_bp = Blueprint("rce", __name__)

@rce_bp.route("/cmd", methods=["GET", "POST"])
def cmd_injection():
    payload = request.args.get("cmd") or request.form.get("cmd") or ""
    
    log_event(current_app.logger if (current_app := request.app) else None, 
              "RCE_ATTEMPT", "HIGH", "T1059", "Execution", payload=payload)
    
    # Save to DB
    from flask import current_app, g
    save_event({
        "timestamp": __import__('datetime').datetime.utcnow().isoformat(),
        "event_type": "RCE_ATTEMPT", "severity": "HIGH", "src_ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""), "payload": payload, "path": request.path,
        "method": request.method, **g.geoip, "mitre_technique_id": "T1059", "mitre_tactic": "Execution", "details": {}
    })

    # Safe Emulation
    if "whoami" in payload:
        return "root", 200
    elif "id" in payload:
        return "uid=0(root) gid=0(root) groups=0(root)", 200
    elif "ls" in payload:
        return "index.html\nconfig.php\n.env", 200
    elif "uname" in payload:
        return "Linux webserver 5.4.0 #1 SMP x86_64 GNU/Linux", 200
    else:
        return f"bash: {payload.split(' ')[0]}: command not found", 200
