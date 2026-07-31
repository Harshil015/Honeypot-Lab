"""Rate-based heuristic anomaly detection."""

import time
from collections import defaultdict, deque
from flask import current_app

traffic_history = defaultdict(deque)
_PRUNE_EVERY_N_CALLS = 500
_calls_since_prune = 0

def _prune_empty_entries() -> None:
    empty_ips = [ip for ip, dq in traffic_history.items() if not dq]
    for ip in empty_ips:
        del traffic_history[ip]

def detect_anomaly(src_ip: str) -> bool:
    """Detects if an IP is sending traffic at an anomalous rate (potential botnet/DoS)."""
    global _calls_since_prune
    current_time = time.time()
    window_seconds = 60
    rate_limit = current_app.config["ML_ANOMALY_RATE_LIMIT"]

    # Clean old timestamps
    while traffic_history[src_ip] and traffic_history[src_ip][0] < current_time - window_seconds:
        traffic_history[src_ip].popleft()

    traffic_history[src_ip].append(current_time)

    _calls_since_prune += 1
    if _calls_since_prune >= _PRUNE_EVERY_N_CALLS:
        _prune_empty_entries()
        _calls_since_prune = 0

    # If IP exceeds normal human browsing rate, flag as anomaly
    if len(traffic_history[src_ip]) > rate_limit:
        return True
    return False
