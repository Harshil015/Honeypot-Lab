"""Scanner and commodity-exploit bait endpoints."""

from __future__ import annotations

import os
import re

from flask import Blueprint, Response, current_app, jsonify, request
from werkzeug.utils import secure_filename

from services.event_logger import get_client_ip, get_user_agent, log_event


bait_bp = Blueprint("bait", __name__)
SHELL_PATHS = ["/shell", "/sh", "/bin/sh", "/bash", "/shell.php", "/cmd.php", "/upload.php"]


@bait_bp.route("/")
def index():
    return "Honeypot running. RCE execution is controlled by HONEYPOT_ENABLE_RCE_EXECUTION."


@bait_bp.route("/api/admin", methods=["POST", "GET"])
def admin_api():
    body = request.get_data(as_text=True)
    log_event("ADMIN_API_ATTEMPT", severity="MEDIUM", payload=body)
    return jsonify({"error": "admin access denied"}), 403


@bait_bp.route("/etc/passwd")
def fake_passwd():
    log_event("FAKE_FILE_READ", severity="LOW", payload="/etc/passwd")
    return """
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    """, 200


@bait_bp.route("/proc/version")
def fake_proc_version():
    log_event("FAKE_FILE_READ", severity="LOW", payload="/proc/version")
    return "Linux version 5.15.0 (gcc version 11.2.0) #1 SMP", 200


@bait_bp.route("/server-status")
def fake_server_status():
    log_event("SERVER_STATUS", severity="LOW")
    return "Server running. Active connections: 4", 200


@bait_bp.route("/cgi-bin/", methods=["GET", "POST"])
def cgi_bin():
    if request.method == "POST":
        body = request.get_data(as_text=True)
        log_event("CGI_POST", severity="HIGH", payload=body)
        return jsonify({"status": "ok", "note": "script executed (simulated)"}), 200

    log_event("CGI_GET", severity="LOW")
    return """
    <html><body>
    <h3>CGI Directory</h3>
    <p>This is a CGI-bin index. You may POST commands here.</p>
    <form method="post">
      cmd: <input name="cmd"><input type="submit">
    </form>
    </body></html>
    """


def make_shell_handler(path):
    def handler(path=path):
        if request.method == "POST":
            if "file" in request.files:
                uploaded_file = request.files["file"]
                original_filename = uploaded_file.filename or "unknown"
                safe_filename = secure_filename(original_filename) or "webshell.bin"
                upload_dir = current_app.config["UPLOAD_DIR"]
                os.makedirs(upload_dir, exist_ok=True)
                destination = os.path.join(upload_dir, safe_filename)
                uploaded_file.save(destination)
                size = os.path.getsize(destination)
                log_event(
                    "WEBSHELL_UPLOAD",
                    severity="HIGH",
                    payload=original_filename,
                    src_ip=get_client_ip(),
                    user_agent=get_user_agent(),
                    details={
                        "path": path,
                        "filename": original_filename,
                        "stored_filename": safe_filename,
                        "size": size,
                    },
                )
                return jsonify({"status": "uploaded", "filename": safe_filename})

            payload = request.get_data(as_text=True)
            log_event(
                "WEBSHELL_POST",
                severity="HIGH",
                payload=payload,
                details={"path": path, "payload_length": len(payload)},
            )
            return jsonify({"out": f"Simulated shell received payload ({len(payload)} bytes)"}), 200

        log_event("WEBSHELL_GET", severity="MEDIUM", details={"path": path})
        return Response(
            f"<html><body><h2>Shell emulator: {path}</h2><p>Usage: POST data or upload a file.</p></body></html>",
            mimetype="text/html",
        )

    return handler


for shell_path in SHELL_PATHS:
    endpoint_name = "shell_emulator_" + re.sub(r"\W+", "_", shell_path).strip("_")
    bait_bp.add_url_rule(
        shell_path,
        endpoint=endpoint_name,
        view_func=make_shell_handler(shell_path),
        methods=["GET", "POST"],
    )


@bait_bp.route("/jndi", methods=["GET", "POST"])
def jndi_bait():
    body = request.get_data(as_text=True)
    headers = {str(key): str(value) for key, value in request.headers.items()}
    log_event("JNDI_ATTEMPT", severity="HIGH", payload=body, details={"headers": headers})
    return jsonify({"status": "ok", "received": True}), 200


@bait_bp.route("/headers", methods=["GET"])
def headers_echo():
    headers = {str(key): str(value) for key, value in request.headers.items()}
    log_event("HEADERS_ECHO", severity="LOW", details={"headers": headers})
    return jsonify({"headers": headers}), 200


@bait_bp.route("/phpmyadmin/", methods=["GET", "POST"])
def phpmyadmin_bait():
    payload = request.get_data(as_text=True)
    log_event("PHPMYADMIN_BAIT", severity="MEDIUM", payload=payload)
    return Response("<html><body><h2>phpMyAdmin</h2><p>Access denied.</p></body></html>", mimetype="text/html"), 403


@bait_bp.route("/manager/html", methods=["GET", "POST"])
def tomcat_manager_bait():
    payload = request.get_data(as_text=True)
    log_event("TOMCAT_MANAGER_BAIT", severity="MEDIUM", payload=payload)
    return Response("<html><body><h2>Tomcat Manager</h2></body></html>", mimetype="text/html"), 401
