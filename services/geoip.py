"""GeoIP enrichment (cached).

issue E1: this used to run synchronously in a before_request hook on
every single live request, blocking the attacker's response for up to
GEOIP_TIMEOUT_SECONDS. It's no longer called from the request path at
all -- events are captured with a "Pending" placeholder (see
services/event_logger.py) and monitor_honeypot.py calls enrich_ip() here
during offline analysis instead, once per unique src_ip rather than once
per request.

issue E4 note: GEOIP_CACHE below is a plain module-level dict, not safe
across multiple processes/workers. Now that enrichment only happens
inside the single, short-lived monitor_honeypot.py analysis process
(rather than a long-running Flask server), the "grows unbounded over
uptime" risk this issue originally described mostly goes away as a side
effect of the E1 fix. It would still need to move to something like Redis
if this were ever called from multiple concurrent worker processes.
"""

import logging
import time
import requests
from flask import current_app

logger = logging.getLogger("honeypot.events")

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
    except requests.Timeout:
        # GeoIP API timeout - use fallback
        pass
    except requests.ConnectionError:
        # GeoIP API unreachable - use fallback
        pass
    except (KeyError, ValueError):
        # Configuration error or JSON parse error - use fallback
        pass
    except Exception as e:
        # Unexpected error - log it (issue E7: this used to be a bare
        # print(), which doesn't show up in honeypot.log or respect the
        # configured log level) and use the fallback.
        logger.warning("Unexpected error in GeoIP enrichment for %s: %s", ip, e)

    fallback = {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "asn": "Unknown"}
    GEOIP_CACHE[ip] = (current_time, fallback)
    return fallback
