"""RCE emulation endpoint with full feature integration."""

from flask import Blueprint, request
from extensions import save_event
from services.event_logger import log_event
import logging

rce_bp = Blueprint("rce", __name__)

_PLAIN_TEXT = {"Content-Type": "text/plain; charset=utf-8"}

@rce_bp.route("/cmd", methods=["GET", "POST"])
def cmd_injection():
    payload = request.args.get("cmd") or request.form.get("cmd") or ""
    logger = logging.getLogger("honeypot.events")
    event_data = log_event(logger, "RCE_ATTEMPT", "HIGH", "T1059", "Execution", payload=payload)
    save_event(event_data)

    if "whoami" in payload:
        return "root", 200, _PLAIN_TEXT
    elif "id" in payload:
        return "uid=0(root) gid=0(root) groups=0(root)", 200, _PLAIN_TEXT
    elif "ls" in payload:
        return "index.html\nconfig.php\n.env", 200, _PLAIN_TEXT
    elif "uname" in payload:
        return "Linux webserver 5.4.0 #1 SMP x86_64 GNU/Linux", 200, _PLAIN_TEXT
    else:
        return f"bash: {payload.split(' ')[0]}: command not found", 200, _PLAIN_TEXT
