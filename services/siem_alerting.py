"""SIEM Webhook integration for real-time alerting."""

import logging
import requests
from flask import current_app

logger = logging.getLogger("honeypot.events")

def send_siem_alert(event: dict):
    """Forwards high-severity events to a configured SIEM/Webhook."""
    webhook_url = current_app.config.get("SIEM_WEBHOOK_URL")
    if not webhook_url:
        return # SIEM not configured

    try:
        # Send as JSON payload, standard for Splunk HEC, Discord, Slack, etc.
        requests.post(webhook_url, json=event, timeout=2.0)
    except Exception as e:
        logger.warning("SIEM alert delivery failed: %s", e)
