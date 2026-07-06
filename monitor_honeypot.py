"""Pandas/Matplotlib log analysis and session replay pipeline."""

import json
import os
import pandas as pd
import matplotlib.pyplot as plt
from tabulate import tabulate

LOGFILE = os.path.join(os.path.dirname(__file__), "honeypot.log")

def load_data() -> pd.DataFrame:
    """Load JSON-lines log file into a Pandas DataFrame."""
    if not os.path.exists(LOGFILE) or os.path.getsize(LOGFILE) == 0:
        print("[-] No logs found. Run app.py first.")
        return pd.DataFrame()
    
    records = []
    with open(LOGFILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
                
    df = pd.DataFrame(records)
    if not df.empty and 'timestamp' in df:
        # errors='coerce' ensures bad timestamps don't crash the script
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
    return df

def generate_charts(df: pd.DataFrame):
    """Generate attack timeline and payload frequency charts."""
    if df.empty:
        return
        
    # Use a copy so we don't mutate the original DataFrame for session_replay
    chart_df = df.copy()
    chart_df.set_index('timestamp', inplace=True)
    
    # Fixed deprecation warning: use '1h' instead of '1H'
    attacks_over_time = chart_df.groupby([pd.Grouper(freq='1h'), 'event_type']).size().unstack(fill_value=0)
    
    plt.figure(figsize=(12, 6))
    if not attacks_over_time.empty:
        attacks_over_time.plot(ax=plt.gca())
    plt.title("Honeypot Interactions Timeline by Attack Vector")
    plt.xlabel("Time")
    plt.ylabel("Number of Requests")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig("attack_timeline.png")
    print("[+] Saved attack_timeline.png")

    plt.figure(figsize=(10, 6))
    top_ips = chart_df['src_ip'].value_counts().head(10)
    if not top_ips.empty:
        top_ips.plot(kind='barh', color='darkred')
    plt.title("Top 10 Attacker Source IPs")
    plt.xlabel("Request Count")
    plt.ylabel("Source IP")
    plt.tight_layout()
    plt.savefig("payload_frequency.png")
    print("[+] Saved payload_frequency.png")

def session_replay(df: pd.DataFrame):
    """Print a structured summary of sessions."""
    if df.empty:
        return
        
    print("\n[*] === Session Replay Summary ===")
    for ip, group in df.groupby('src_ip'):
        print(f"\n[+] Attacker IP: {ip} ({group.iloc[0].get('country', 'Unknown')})")
        print(f"    Total Hits: {len(group)}")
        print(f"    First Seen: {group['timestamp'].min()}")
        print(f"    Last Seen: {group['timestamp'].max()}")
        
        # Extract kill chain (limit to 5 events for readability)
        kill_chain = group[['timestamp', 'event_type', 'path']].head(5).copy()
        # Format timestamp to string for nicer tabulate output
        kill_chain['timestamp'] = kill_chain['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        
        print(tabulate(kill_chain, headers="keys", tablefmt="grid", showindex=False))

def main():
    print("[*] Loading honeypot data...")
    df = load_data()
    if df.empty:
        return
        
    print(f"[+] Loaded {len(df)} events.")
    generate_charts(df)
    session_replay(df)

if __name__ == "__main__":
    main()
