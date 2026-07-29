"""Pandas/Matplotlib log analysis, session replay, and YARA generation."""

import json
import os
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from tabulate import tabulate

from config import Config
from extensions import EVENT_COLUMNS

LOGFILE = os.path.join(os.path.dirname(__file__), "honeypot.log")


def load_data_from_db() -> pd.DataFrame:
    """Load events from the SQLite store.

    issue D1: events.db was write-only -- save_event() wrote to it on
    every request, but nothing in the codebase ever read it back. This is
    now the preferred source (WAL mode + indices make it the schema's
    evident intent as the real analytics store); load_data() falls back
    to honeypot.log if it's empty or missing.
    """
    db_path = Config.DATABASE_PATH
    if not os.path.exists(db_path):
        return pd.DataFrame()
    try:
        with sqlite3.connect(db_path) as conn:
            df = pd.read_sql_query(f"SELECT {', '.join(EVENT_COLUMNS)} FROM events", conn)
    except (sqlite3.Error, pd.errors.DatabaseError) as e:
        print(f"[!] Warning: could not read events.db ({e}); falling back to honeypot.log")
        return pd.DataFrame()

    if df.empty:
        return df
    if "timestamp" in df:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])
    for json_col in ("details", "iocs"):
        if json_col in df:
            df[json_col] = df[json_col].apply(lambda v: json.loads(v) if isinstance(v, str) and v else {})
    if "ml_anomaly" in df:
        df["ml_anomaly"] = df["ml_anomaly"].astype(bool)
    return df


def load_data_from_log() -> pd.DataFrame:
    """Load events from the honeypot.log JSON-lines file."""
    if not os.path.exists(LOGFILE) or os.path.getsize(LOGFILE) == 0:
        return pd.DataFrame()
    records = []
    with open(LOGFILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip malformed JSON lines
                continue
            except Exception as e:
                # Log other unexpected errors for debugging
                print(f"[!] Warning: Unexpected error parsing log line: {e}")
                continue
    df = pd.DataFrame(records)
    if not df.empty and "timestamp" in df:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])
    return df


def load_data() -> pd.DataFrame:
    """Prefer events.db; fall back to honeypot.log if it's empty/missing (issue D1)."""
    df = load_data_from_db()
    if not df.empty:
        print(f"[+] Loaded {len(df)} events from events.db")
        return df
    print("[*] events.db empty or missing, falling back to honeypot.log")
    df = load_data_from_log()
    if df.empty:
        print("[-] No logs found.")
    return df


def enrich_geoip_offline(df: pd.DataFrame) -> pd.DataFrame:
    """GeoIP-enrich the loaded events, once per unique src_ip, entirely
    offline / after capture.

    issue E1: this used to run synchronously on every single live request
    (blocking the attacker's response for up to GEOIP_TIMEOUT_SECONDS).
    Captured events now carry "Pending" placeholders; this is where they
    actually get filled in, deduplicated by IP so N events from the same
    attacker cost one lookup rather than N.
    """
    if df.empty or "src_ip" not in df or "country" not in df:
        return df
    pending_mask = df["country"] == "Pending"
    if not pending_mask.any():
        return df

    from flask import Flask
    from services.geoip import enrich_ip

    minimal_app = Flask(__name__)
    minimal_app.config.from_object(Config)

    unique_ips = df.loc[pending_mask, "src_ip"].dropna().unique().tolist()
    print(f"[*] Enriching GeoIP for {len(unique_ips)} unique IP(s) offline (not on the honeypot's request path)...")
    with minimal_app.app_context():
        lookups = {ip: enrich_ip(ip) for ip in unique_ips}

    for idx in df.index[pending_mask]:
        data = lookups.get(df.at[idx, "src_ip"])
        if not data:
            continue
        for field in ("country", "city", "isp", "asn"):
            df.at[idx, field] = data.get(field, df.at[idx, field])
    return df


def generate_charts(df: pd.DataFrame):
    if df.empty: return
    chart_df = df.copy()
    chart_df.set_index('timestamp', inplace=True)
    attacks_over_time = chart_df.groupby([pd.Grouper(freq='1h'), 'event_type']).size().unstack(fill_value=0)
    
    plt.figure(figsize=(12, 6))
    if not attacks_over_time.empty: attacks_over_time.plot(ax=plt.gca())
    plt.title("Honeypot Interactions Timeline")
    plt.tight_layout()
    plt.savefig("attack_timeline.png")
    plt.close()
    print("[+] Saved attack_timeline.png")


def generate_payload_frequency_chart(df: pd.DataFrame):
    """issue C1: User_Manual.md documented this chart, but the function
    generating it never existed -- running the documented command produced
    attack_timeline.png and silently skipped payload_frequency.png with no
    error.
    """
    if df.empty or "payload" not in df:
        return
    payloads = df["payload"].fillna("").astype(str).replace("", "(empty)")
    truncated = payloads.apply(lambda p: p if len(p) <= 40 else p[:37] + "...")
    # Matplotlib treats an unescaped '$' as the start of a mathtext
    # expression. Real payloads here often contain one (e.g. Log4Shell's
    # ${jndi:...}), and truncation can cut it off before a closing '$',
    # leaving unbalanced mathtext that crashes the chart - escape it so
    # '$' always renders as a literal character in the tick labels.
    truncated = truncated.str.replace("$", "\\$", regex=False)
    top_payloads = truncated.value_counts().head(15)
    if top_payloads.empty:
        return

    plt.figure(figsize=(10, 8))
    top_payloads.sort_values().plot(kind="barh")
    plt.title("Top 15 Payloads by Frequency")
    plt.xlabel("Occurrences")
    plt.tight_layout()
    plt.savefig("payload_frequency.png")
    plt.close()
    print("[+] Saved payload_frequency.png")


def _escape_yara_string(payload: str, max_len: int = 100) -> str:
    """Escape a payload for safe embedding in a YARA double-quoted string
    (issue D9). The raw payload is truncated to max_len *before* escaping,
    not after: escaping can only grow a string (never shrinks it), so
    truncating first guarantees the escape sequences that result are never
    cut in half. Truncating after escaping instead risks leaving a
    dangling, unescaped backslash at the cut point, which would corrupt
    the generated rule's syntax.
    """
    truncated = payload[:max_len]
    escaped = truncated.replace('\\', '\\\\').replace('"', '\\"')
    # A YARA string literal must be a single line - strip/space out any
    # embedded newlines, carriage returns, or other control characters.
    return ''.join(ch if ch.isprintable() else ' ' for ch in escaped).strip()


def generate_yara_rules(df: pd.DataFrame):
    """Feature 3: Generate YARA rules from observed payloads."""
    if df.empty or 'payload' not in df:
        return

    print("\n[*] Generating YARA rules from captured payloads...")
    seen_payloads = set()
    yara_rules = []
    for _, row in df.iterrows():
        payload = str(row.get('payload', ''))
        if len(payload) <= 10:  # Only generate rules for substantial payloads
            continue
        if payload in seen_payloads:
            # issue D8: 50 identical payloads used to produce 50 near-
            # duplicate rules (only the rule name differed) instead of one.
            continue
        seen_payloads.add(payload)

        safe_payload = _escape_yara_string(payload)
        if not safe_payload:
            continue
        rule_name = f"rule_honeypot_payload_{len(yara_rules) + 1}"
        yara_rules.append(
            f'rule {rule_name} {{\n    strings:\n        $a = "{safe_payload}"\n    condition:\n        $a\n}}'
        )

    if yara_rules:
        with open("generated_rules.yar", "w") as f:
            f.write("\n\n".join(yara_rules))
        print(f"[+] Saved {len(yara_rules)} rules to generated_rules.yar")


def session_replay(df: pd.DataFrame):
    if df.empty: return
    print("\n[*] === Session Replay Summary ===")
    for ip, group in df.groupby('src_ip'):
        print(f"\n[+] Attacker IP: {ip} ({group.iloc[0].get('country', 'Unknown')})")
        print(f"    Total Hits: {len(group)} | ML Anomaly: {group.iloc[0].get('ml_anomaly', False)}")
        kill_chain = group[['timestamp', 'event_type', 'path']].head(5).copy()
        kill_chain['timestamp'] = kill_chain['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        print(tabulate(kill_chain, headers="keys", tablefmt="grid", showindex=False))


def main():
    print("[*] Loading honeypot data...")
    df = load_data()
    if df.empty: return
    print(f"[+] Loaded {len(df)} events.")
    df = enrich_geoip_offline(df)
    generate_charts(df)
    generate_payload_frequency_chart(df)
    generate_yara_rules(df)
    session_replay(df)

if __name__ == "__main__":
    main()
