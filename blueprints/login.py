"""Brute-force login capture."""

from flask import Blueprint, request
from extensions import save_event
from services.event_logger import log_event
import logging

login_bp = Blueprint("login", __name__)

@login_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        payload = f"{username}:{password}"

        logger = logging.getLogger("honeypot.events")
        event_data = log_event(logger, "BRUTE_FORCE", "MEDIUM", "T1110", "Credential Access", payload=payload)
        save_event(event_data)
        return "Invalid credentials", 401

    return "<form method='post'>Username: <input name='username'><br>Password: <input name='password' type='password'><br><button>Login</button></form>", 200
