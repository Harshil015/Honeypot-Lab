"""Application configuration for the honeypot lab."""

from __future__ import annotations
import os
import socket
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    LOG_FILE = os.getenv("HONEYPOT_LOG_FILE", str(BASE_DIR / "honeypot.log"))
    LOG_LEVEL = os.getenv("HONEYPOT_LOG_LEVEL", "INFO").upper()

    DB_DIR = Path(os.getenv("HONEYPOT_DB_DIR", str(BASE_DIR / "db")))
    DATABASE_PATH = os.getenv("HONEYPOT_DATABASE_PATH", str(DB_DIR / "events.db"))

    UPLOAD_DIR = os.getenv("HONEYPOT_UPLOAD_DIR", str(BASE_DIR / "uploads"))
    
    # Feature 4: Multi-Node Support
    NODE_ID = os.getenv("HONEYPOT_NODE_ID", socket.gethostname())

    # Feature 1: SIEM Integration (Webhook for Splunk/Slack/Discord/ELK)
    SIEM_WEBHOOK_URL = os.getenv("SIEM_WEBHOOK_URL", "") # Leave empty to disable

    # Anomaly detection threshold. This is a rate-based heuristic (see
    # services/anomaly_detector.py), not a trained ML model -- issue C3.
    ML_ANOMALY_RATE_LIMIT = int(os.getenv("ML_ANOMALY_RATE_LIMIT", "20")) # Hits per minute

    GEOIP_ENABLED = os.getenv("HONEYPOT_GEOIP_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
    GEOIP_TIMEOUT_SECONDS = float(os.getenv("HONEYPOT_GEOIP_TIMEOUT_SECONDS", "2.0"))
    GEOIP_ENDPOINT = os.getenv("HONEYPOT_GEOIP_ENDPOINT", "http://ip-api.com/json/{ip}")

    # issue A1: X-Forwarded-For is only trusted when the connecting peer's
    # address is in this set. Empty by default -- this project is deployed
    # as a directly-exposed Flask dev server per the README, so trusting
    # the header unconditionally lets any attacker spoof their own logged
    # src_ip. Set HONEYPOT_TRUSTED_PROXY_IPS to a comma-separated allowlist
    # if you put a real reverse proxy in front of this.
    TRUSTED_PROXY_IPS = frozenset(
        ip.strip() for ip in os.getenv("HONEYPOT_TRUSTED_PROXY_IPS", "").split(",") if ip.strip()
    )

    # issue E5: previously unset, so /upload accepted a file of any size up
    # to whatever the disk allows. 10 MB is plenty for a captured webshell
    # and small enough to not be a useful disk-filling vector.
    MAX_CONTENT_LENGTH = int(os.getenv("HONEYPOT_MAX_CONTENT_LENGTH_BYTES", str(10 * 1024 * 1024)))
