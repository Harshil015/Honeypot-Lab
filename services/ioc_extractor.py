"""Automated IOC (Indicator of Compromise) extraction."""

import re
import ipaddress

# IPv4 candidate pattern - validated below via ipaddress (rejects e.g. 999.1.1.1).
_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_IPV6_RE = re.compile(r'(?<![A-Fa-f0-9:.])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:.])')
_URL_RE = re.compile(r'(?:https?|ldaps?|rmi|dns)://[^\s<>"\'}\)]+')
_MD5_RE = re.compile(r'\b[A-Fa-f0-9]{32}\b')
_SHA1_RE = re.compile(r'\b[A-Fa-f0-9]{40}\b')
_SHA256_RE = re.compile(r'\b[A-Fa-f0-9]{64}\b')

def extract_iocs(payload: str) -> dict:
    """Extracts IPv4/IPv6 addresses, URLs, and MD5/SHA-1/SHA-256 hashes from a string."""
    if not payload:
        return {"ips": [], "urls": [], "hashes": []}

    # Extract potential IPs (v4 + v6 candidates) and validate them
    potential_ips = _IPV4_RE.findall(payload) + _IPV6_RE.findall(payload)
    valid_ips = []
    seen_ips = set()
    for ip in potential_ips:
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        try:
            # Validate it's a real IPv4/IPv6 address (rejects e.g. octets > 255)
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            # Invalid IP address, skip it
            pass

    hashes = set(_SHA256_RE.findall(payload)) | set(_SHA1_RE.findall(payload)) | set(_MD5_RE.findall(payload))

    return {
        "ips": valid_ips,
        "urls": list(set(_URL_RE.findall(payload))),
        "hashes": list(hashes)
    }
