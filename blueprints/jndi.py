"""JNDI / Log4Shell capture."""

from flask import Blueprint, request
from extensions import save_event
from services.event_logger import log_event
import logging

jndi_bp = Blueprint("jndi", __name__)

@jndi_bp.route("/jndi", methods=["GET", "POST"])
def jndi_lookup():
    user_agent = request.headers.get("User-Agent") or ""
    payload = f"{user_agent} {request.args.get('payload', '')}".strip()

    logger = logging.getLogger("honeypot.events")
    event_data = log_event(logger, "JNDI_INJECTION", "CRITICAL", "T1059", "Execution", payload=payload)
    save_event(event_data)

    return "OK", 200
