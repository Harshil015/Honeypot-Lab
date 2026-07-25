"""Automated IOC (Indicator of Compromise) extraction."""

import re
import ipaddress

def extract_iocs(payload: str) -> dict:
    """Extracts IPs, URLs, and SHA256 hashes from a string."""
    if not payload:
        return {"ips": [], "urls": [], "hashes": []}

    # IP regex pattern - matches potential IPv4 addresses
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    # URL regex pattern
    url_regex = r'https?://[^\s<>"\']+'
    # SHA256 hash regex pattern (64 hex characters)
    hash_regex = r'\b[A-Fa-f0-9]{64}\b'

    # Extract potential IPs and validate them
    potential_ips = re.findall(ip_regex, payload)
    valid_ips = []
    for ip in set(potential_ips):
        try:
            # Validate that it's a proper IPv4 address (octets must be 0-255)
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            # Invalid IP address, skip it
            pass

    return {
        "ips": valid_ips,
        "urls": list(set(re.findall(url_regex, payload))),
        "hashes": list(set(re.findall(hash_regex, payload)))
    }
