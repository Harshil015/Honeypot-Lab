"""ML-based statistical anomaly detection layer."""

import time
from collections import defaultdict, deque
from flask import current_app

# Sliding window memory: {ip: deque([timestamps])}
traffic_history = defaultdict(deque)

def detect_anomaly(src_ip: str) -> bool:
    """Detects if an IP is sending traffic at an anomalous rate (potential botnet/DoS)."""
    current_time = time.time()
    window_seconds = 60
    rate_limit = current_app.config["ML_ANOMALY_RATE_LIMIT"]

    # Clean old timestamps
    while traffic_history[src_ip] and traffic_history[src_ip][0] < current_time - window_seconds:
        traffic_history[src_ip].popleft()

    traffic_history[src_ip].append(current_time)
    
    # If IP exceeds normal human browsing rate, flag as anomaly
    if len(traffic_history[src_ip]) > rate_limit:
        return True
    return False
