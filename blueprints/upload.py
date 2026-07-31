"""File upload capture."""

from flask import Blueprint, request
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from extensions import save_event
from services.event_logger import log_event
from services.ioc_extractor import extract_iocs
import logging
import os

upload_bp = Blueprint("upload", __name__)

IOC_SCAN_MAX_BYTES = 1 * 1024 * 1024  # 1 MB


def _unique_filepath(directory: str, filename: str) -> str:
    filepath = os.path.join(directory, filename)
    if not os.path.exists(filepath):
        return filepath
    stem, ext = os.path.splitext(filename)
    timestamped = f"{stem}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}{ext}"
    return os.path.join(directory, timestamped)


@upload_bp.route("/upload", methods=["POST"])
def upload_file():
    app = upload_bp.app
    if "file" not in request.files:
        return "No file provided", 400

    file = request.files["file"]
    
    filename = secure_filename(file.filename or "")
    if not filename:
        filename = f"upload_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}.bin"

    filepath = _unique_filepath(app.config["UPLOAD_DIR"], filename)
    
    saved_filename = os.path.basename(filepath)
    
    file.save(filepath)
    
    file_iocs = {"ips": [], "urls": [], "hashes": []}
    try:
        with open(filepath, "rb") as f:
            content_bytes = f.read(IOC_SCAN_MAX_BYTES)
        file_iocs = extract_iocs(content_bytes.decode("utf-8", errors="ignore"))
    except OSError:
        pass

    logger = logging.getLogger("honeypot.events")
    event_data = log_event(
        logger, "WEBSHELL_UPLOAD", "HIGH", "T1505.003", "Persistence",
        payload=saved_filename,
        details={"saved_to": filepath, "original_filename": file.filename, "content_iocs": file_iocs},
    )
    save_event(event_data)

    return "File uploaded successfully", 200
