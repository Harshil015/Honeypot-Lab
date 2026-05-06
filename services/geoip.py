"""GeoIP enrichment using ip-api.com."""

from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from flask import current_app


_EMPTY_GEO = {"country": None, "city": None, "isp": None, "asn": None}


def _is_public_ip(ip_address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return False
    return parsed.is_global


@lru_cache(maxsize=2048)
def _lookup_geoip_cached(ip_address: str, endpoint: str, timeout: float) -> dict:
    url = endpoint.format(ip=ip_address)
    with urlopen(url, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    if data.get("status") != "success":
        return dict(_EMPTY_GEO)
    return {
        "country": data.get("country"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "asn": data.get("as"),
    }


def enrich_ip(ip_address: str) -> dict:
    """Return GeoIP metadata for a public IP, or empty fields on failure."""
    if not current_app.config.get("GEOIP_ENABLED", True) or not _is_public_ip(ip_address):
        return dict(_EMPTY_GEO)

    try:
        return _lookup_geoip_cached(
            ip_address,
            current_app.config["GEOIP_ENDPOINT"],
            current_app.config["GEOIP_TIMEOUT_SECONDS"],
        )
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return dict(_EMPTY_GEO)
