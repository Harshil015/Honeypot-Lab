"""Pandas/Matplotlib log analysis, session replay, and YARA generation."""

import json
import os
import pandas as pd
import matplotlib.pyplot as plt
from tabulate import tabulate
import yaml

LOGFILE = os.path.join(os.path.dirname(__file__), "honeypot.log")

def load_data() -> pd.DataFrame:
    if not os.path.exists(LOGFILE) or os.path.getsize(LOGFILE) == 0:
        print("[-] No logs found.")
        return pd.DataFrame()
    records = []
    with open(LOGFILE, "r", encoding="utf-8") as f:
        for line in f:
            try: records.append(json.loads(line))
            except: continue
    df = pd.DataFrame(records)
    if not df.empty and 'timestamp' in df:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
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
    print("[+] Saved attack_timeline.png")

def generate_yara_rules(df: pd.DataFrame):
    """Feature 3: Generate YARA rules from observed payloads."""
    if df.empty or 'payload' not in df: return
    
    print("\n[*] Generating YARA rules from captured payloads...")
    yara_rules = []
    for idx, row in df.iterrows():
        payload = str(row.get('payload', ''))
        if len(payload) > 10: # Only generate rules for substantial payloads
            rule_name = f"rule_honeypot_payload_{idx}"
            # Escape quotes for YARA string
            safe_payload = payload.replace('"', '\\"')[:100] 
            yara_rules.append(f'rule {rule_name} {{\n    strings:\n        $a = "{safe_payload}"\n    condition:\n        $a\n}}')
    
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
    generate_charts(df)
    generate_yara_rules(df)
    session_replay(df)

if __name__ == "__main__":
    main()
