"""Cached GeoIP enrichment."""

import time
import requests
from flask import current_app

GEOIP_CACHE = {}
GEOIP_TTL = 3600  # 1 hour cache

def enrich_ip(ip: str) -> dict:
    """Return cached GeoIP data or fetch from API."""
    if ip == "127.0.0.1" or ip == "0.0.0.0":
        return {"country": "LOCAL", "city": "LOCAL", "isp": "LOCAL", "asn": "LOCAL"}

    current_time = time.time()
    if ip in GEOIP_CACHE:
        cached_time, cached_data = GEOIP_CACHE[ip]
        if current_time - cached_time < GEOIP_TTL:
            return cached_data

    if not current_app.config["GEOIP_ENABLED"]:
        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "asn": "Unknown"}

    try:
        endpoint = current_app.config["GEOIP_ENDPOINT"].format(ip=ip)
        resp = requests.get(endpoint, timeout=current_app.config["GEOIP_TIMEOUT_SECONDS"])
        if resp.status_code == 200:
            data = resp.json()
            enriched = {
                "country": data.get("countryCode", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "asn": data.get("as", "Unknown")
            }
            GEOIP_CACHE[ip] = (current_time, enriched)
            return enriched
    except Exception:
        pass
    
    fallback = {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "asn": "Unknown"}
    GEOIP_CACHE[ip] = (current_time, fallback)
    return fallback
