"""Fake login portal blueprint."""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from services.event_logger import get_client_ip, get_user_agent, log_event


login_bp = Blueprint("login", __name__)


@login_bp.route("/login", methods=["GET", "POST"])
def fake_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        log_event(
            "LOGIN_ATTEMPT",
            severity="MEDIUM",
            payload=f"username={username} password={password}",
            src_ip=get_client_ip(),
            user_agent=get_user_agent(),
            details={"username": username, "password": password},
        )
        return jsonify({"status": "failed", "message": "Invalid username or password"}), 401

    return """
    <html>
        <body>
            <h2>Login Portal</h2>
            <form action="/login" method="post">
                Username: <input name="username"><br>
                Password: <input name="password" type="password"><br>
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """
