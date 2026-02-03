
# monitor_honeypot.py - simple live log viewer for honeypot.log
import time
import os
import re

try:
    from tabulate import tabulate
    USE_TABULATE = True
except ImportError:
    USE_TABULATE = False

LOGFILE = os.path.join(os.path.dirname(__file__), "honeypot.log")

PATTERN = re.compile(
    r"HTTP_CMD src=(?P<src>\S+) ua=(?P<ua>.+?) cmd=(?P<cmd>.*)$"
)

def follow(filename):
    """
    Generator that yields new lines as they are written to the file.
    Similar to 'tail -f'.
    """
    with open(filename, "r") as f:
        # Go to end of file
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")

def parse_line(line):
    """
    Extract src IP, user-agent, and cmd from a log line.
    If it doesn't match our pattern, return raw.
    """
    m = PATTERN.search(line)
    if not m:
        return {"raw": line}

    return {
        "src": m.group("src"),
        "ua": m.group("ua"),
        "cmd": m.group("cmd"),
        "raw": line
    }

def display_entry(entry):
    if "src" in entry:
        if USE_TABULATE:
            table = [[entry["src"], entry["ua"], entry["cmd"]]]
            print(tabulate(table, headers=["Source IP", "User-Agent", "Command"], tablefmt="grid"))
        else:
            print(f"[SRC] {entry['src']}")
            print(f"[UA ] {entry['ua']}")
            print(f"[CMD] {entry['cmd']}")
            print("-" * 60)
    else:
        print(entry["raw"])

def main():
    if not os.path.exists(LOGFILE):
        print(f"{LOGFILE} does not exist yet. Start app.py first or send some requests.")
        open(LOGFILE, "a").close()

    print(f"[*] Monitoring {LOGFILE} for new events...")
    for line in follow(LOGFILE):
        entry = parse_line(line)
        display_entry(entry)

if __name__ == "__main__":
    main()
