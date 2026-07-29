"""Rate-based heuristic anomaly detection.

issue C3: this was previously described (in the README and this file's
own docstring) as "ML-based anomaly detection." What's actually
implemented is a sliding-window request-rate counter: more than
ML_ANOMALY_RATE_LIMIT requests from one IP in 60 seconds is flagged.
There is no model, no training, and no statistical fitting -- it's a
threshold, not machine learning. The behavior below is unchanged; only
the description of what it is has been corrected, since overclaiming this
is the kind of thing worth being precise about (e.g. if this project comes
up in an interview). A real statistical/ML approach -- e.g. a z-score
over each IP's historical request rate, or an isolation forest on request
features -- would be a reasonable future enhancement.
"""

import time
from collections import defaultdict, deque
from flask import current_app

# Sliding window memory: {ip: deque([timestamps])}
traffic_history = defaultdict(deque)

# issue E4: the outer dict never removed an IP's key once created (only
# the per-IP deque got trimmed), so it grew for the lifetime of the
# process -- worse combined with issue A1, since a spoofed src_ip could
# inflate this indefinitely. Every _PRUNE_EVERY_N_CALLS calls, drop keys
# whose deque has emptied out.
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
