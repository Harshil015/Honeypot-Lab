"""Automated IOC (Indicator of Compromise) extraction."""

import re

def extract_iocs(payload: str) -> dict:
    """Extracts IPs, URLs, and SHA256 hashes from a string."""
    if not payload:
        return {"ips": [], "urls": [], "hashes": []}

    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    url_regex = r'https?://[^\s<>"\']+'
    hash_regex = r'\b[A-Fa-f0-9]{64}\b' # SHA256

    return {
        "ips": list(set(re.findall(ip_regex, payload))),
        "urls": list(set(re.findall(url_regex, payload))),
        "hashes": list(set(re.findall(hash_regex, payload)))
    }
