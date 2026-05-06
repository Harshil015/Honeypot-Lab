"""Remote-command-execution honeypot endpoint."""

from __future__ import annotations

import subprocess

from flask import Blueprint, current_app, jsonify, request

from services.event_logger import get_client_ip, get_user_agent, log_event


rce_bp = Blueprint("rce", __name__)


@rce_bp.route("/vulnerable")
def vulnerable():
    """Capture RCE attempts and optionally execute commands in lab mode."""
    cmd = request.args.get("cmd", "")
    src_ip = get_client_ip()
    user_agent = get_user_agent()

    log_event(
        "RCE_ATTEMPT",
        severity="CRITICAL",
        payload=cmd,
        src_ip=src_ip,
        user_agent=user_agent,
        details={"execution_enabled": current_app.config["ENABLE_RCE_EXECUTION"]},
    )

    if not cmd:
        return jsonify({"error": "no cmd parameter provided"}), 400

    if not current_app.config["ENABLE_RCE_EXECUTION"]:
        return jsonify(
            {
                "status": "captured",
                "source_ip": src_ip,
                "user_agent": user_agent,
                "cmd": cmd,
                "execution_enabled": False,
            }
        )

    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        return_code = proc.returncode

        log_event(
            "RCE_RESULT",
            severity="HIGH",
            payload=cmd,
            src_ip=src_ip,
            user_agent=user_agent,
            details={"return_code": return_code, "stdout": stdout, "stderr": stderr},
        )

        return jsonify(
            {
                "status": "executed",
                "source_ip": src_ip,
                "user_agent": user_agent,
                "cmd": cmd,
                "return_code": return_code,
                "stdout": stdout,
                "stderr": stderr,
            }
        )

    except subprocess.TimeoutExpired:
        log_event(
            "RCE_TIMEOUT",
            severity="HIGH",
            payload=cmd,
            src_ip=src_ip,
            user_agent=user_agent,
        )
        return jsonify({"status": "timeout", "cmd": cmd}), 504

    except Exception as exc:  # noqa: BLE001 - log unexpected honeypot execution errors
        log_event(
            "RCE_ERROR",
            severity="HIGH",
            payload=cmd,
            src_ip=src_ip,
            user_agent=user_agent,
            details={"error": str(exc)},
        )
        return jsonify({"status": "error", "error": str(exc)}), 500
