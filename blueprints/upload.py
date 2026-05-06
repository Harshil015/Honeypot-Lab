"""File upload honeypot blueprint."""

from __future__ import annotations

import os

from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from services.event_logger import get_client_ip, get_user_agent, log_event


upload_bp = Blueprint("upload", __name__)


@upload_bp.route("/upload", methods=["POST"])
def fake_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files["file"]
    original_filename = uploaded_file.filename or "unknown"
    safe_filename = secure_filename(original_filename) or "uploaded.bin"
    upload_dir = current_app.config["UPLOAD_DIR"]
    os.makedirs(upload_dir, exist_ok=True)

    file_path = os.path.join(upload_dir, safe_filename)
    uploaded_file.save(file_path)
    file_size = os.path.getsize(file_path)

    log_event(
        "FILE_UPLOAD",
        severity="HIGH",
        payload=original_filename,
        src_ip=get_client_ip(),
        user_agent=get_user_agent(),
        details={
            "filename": original_filename,
            "stored_filename": safe_filename,
            "size": file_size,
        },
    )

    return jsonify({"status": "uploaded", "filename": safe_filename, "size": file_size})
