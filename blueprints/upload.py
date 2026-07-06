"""File upload capture."""

from flask import Blueprint, request, g
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from extensions import save_event
from services.event_logger import log_event, get_client_ip
import logging
import os

upload_bp = Blueprint("upload", __name__)

@upload_bp.route("/upload", methods=["POST"])
def upload_file():
    app = upload_bp.app
    if "file" not in request.files:
        return "No file provided", 400
    
    file = request.files["file"]
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_DIR"], filename)
    
    # Save file for analysis (safe, never executed)
    file.save(filepath)
    
    logger = logging.getLogger("honeypot.events")
    log_event(logger, "WEBSHELL_UPLOAD", "HIGH", "T1505.003", "Persistence", payload=filename)
    
    save_event({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "WEBSHELL_UPLOAD", "severity": "HIGH", "src_ip": get_client_ip(),
        "user_agent": request.headers.get("User-Agent", ""), "payload": filename, "path": request.path,
        "method": request.method, **g.geoip, "mitre_technique_id": "T1505.003", "mitre_tactic": "Persistence", "details": {"saved_to": filepath}
    })
    
    return "File uploaded successfully", 200
