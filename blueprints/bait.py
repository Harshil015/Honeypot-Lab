"""Botnet bait endpoints."""

from flask import Blueprint, request
from extensions import save_event
from services.event_logger import log_event
import logging

bait_bp = Blueprint("bait", __name__)

@bait_bp.route("/shell.php", methods=["GET", "POST"])
@bait_bp.route("/cmd.php", methods=["GET", "POST"])
@bait_bp.route("/cgi-bin/", methods=["GET", "POST"])
def bait_endpoints():
    # issue D10: this used to be str(request.args) + str(request.form),
    # which logs the *repr* of the MultiDict objects -- a bare hit with no
    # query string or body used to log the literal text
    # "ImmutableMultiDict([])ImmutableMultiDict([])" as the payload instead
    # of an empty string. Using the raw query string and body instead
    # gives the actual bytes an attacker sent.
    parts = [p for p in (request.query_string.decode(errors="replace"), request.get_data(as_text=True)) if p]
    payload = " ".join(parts)

    logger = logging.getLogger("honeypot.events")
    event_data = log_event(logger, "BAIT_HIT", "LOW", "T1190", "Initial Access", payload=payload)
    save_event(event_data)

    return "Not Found", 404
