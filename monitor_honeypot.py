"""Simple live JSON event viewer for honeypot.log."""

from __future__ import annotations

import json
import os
import time

from tabulate import tabulate


LOGFILE = os.path.join(os.path.dirname(__file__), "honeypot.log")


def follow(filename):
    """Yield new lines as they are written, similar to tail -f."""
    with open(filename, "r", encoding="utf-8") as log_file:
        log_file.seek(0, os.SEEK_END)
        while True:
            line = log_file.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def parse_line(line):
    """Parse a JSON-lines event, preserving raw text if parsing fails."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return {"raw": line}

    if not isinstance(event, dict):
        return {"raw": line}
    event["raw"] = line
    return event


def display_entry(entry):
    if "event_type" not in entry:
        print(entry["raw"])
        return

    row = [
        entry.get("timestamp", ""),
        entry.get("severity", ""),
        entry.get("event_type", ""),
        entry.get("src_ip", ""),
        entry.get("country") or "",
        entry.get("mitre_technique_id") or "",
        entry.get("payload") or "",
    ]
    print(
        tabulate(
            [row],
            headers=["Timestamp", "Severity", "Event", "Source IP", "Country", "MITRE", "Payload"],
            tablefmt="grid",
        )
    )


def main():
    if not os.path.exists(LOGFILE):
        print(f"{LOGFILE} does not exist yet. Start app.py first or send some requests.")
        open(LOGFILE, "a", encoding="utf-8").close()

    print(f"[*] Monitoring {LOGFILE} for new structured events...")
    for line in follow(LOGFILE):
        display_entry(parse_line(line))


if __name__ == "__main__":
    main()
