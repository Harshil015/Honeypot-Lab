"""Application configuration for the honeypot lab."""

from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Default configuration with environment-variable overrides."""

    LOG_FILE = os.getenv("HONEYPOT_LOG_FILE", str(BASE_DIR / "honeypot.log"))
    LOG_LEVEL = os.getenv("HONEYPOT_LOG_LEVEL", "INFO").upper()

    DB_DIR = Path(os.getenv("HONEYPOT_DB_DIR", str(BASE_DIR / "db")))
    DATABASE_PATH = os.getenv("HONEYPOT_DATABASE_PATH", str(DB_DIR / "events.db"))

    UPLOAD_DIR = os.getenv("HONEYPOT_UPLOAD_DIR", str(BASE_DIR / "uploads"))
    ENABLE_RCE_EXECUTION = os.getenv("HONEYPOT_ENABLE_RCE_EXECUTION", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    GEOIP_ENABLED = os.getenv("HONEYPOT_GEOIP_ENABLED", "true").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    GEOIP_TIMEOUT_SECONDS = float(os.getenv("HONEYPOT_GEOIP_TIMEOUT_SECONDS", "2.0"))
    GEOIP_ENDPOINT = os.getenv("HONEYPOT_GEOIP_ENDPOINT", "http://ip-api.com/json/{ip}")
