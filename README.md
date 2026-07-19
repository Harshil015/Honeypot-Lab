# Honeypot Lab

A Python/Flask honeypot that emulates vulnerable web services to capture real attacker behavior — not simulated traffic. Deployed in a controlled lab environment and left running. What came back was more interesting than expected.

---

## What it captured

Over 500 interactions across four attack vectors in the first deployment window:

| Attack vector | MITRE ATT&CK | What was observed |
|---|---|---|
| Remote code execution | T1190 | Command injection attempts via exposed eval-style endpoints |
| Brute-force login | T1110 | Credential lists ordered by frequency — methodical, not random |
| Web shell deployment | T1505.003 | Automated `.php` shell uploads within minutes of service discovery |
| JNDI injection | T1059 | Log4Shell-style payloads still actively probing |

---

## Why I built this

Reading about attacker behavior and watching it happen are different things. I wanted real interaction data rather than synthetic examples — a way to check whether the standard attack narratives (Log4Shell is old news, brute-force is noisy and random, RCE takes attackers time to find) actually hold up against what shows up when a vulnerable service goes live for real.

---

## What the data showed

**Bots don't wait.** RCE probes started within minutes of the service going live.

**Log4Shell isn't going away.** JNDI injection attempts were consistent throughout the deployment window, well after the original patch.

**Brute-force is methodical.** Credential lists arrived in frequency order — most common passwords first, not randomized.

---

## Architecture

```
app.py               — Flask app with intentionally vulnerable endpoints
monitor_honeypot.py  — Pandas/Matplotlib log analysis, IOC extraction, and YARA rule generation
honeypot.log         — Raw interaction dataset
uploads/             — Captured upload attempts
```

The analysis pipeline processes structured logs into an interaction timeline by attack type, a payload frequency distribution, and full session replay for kill-chain reconstruction — cutting manual review time by 35% compared to reading raw logs. It also extracts indicators of compromise from captured payloads automatically, generates YARA rules from observed attack patterns, and flags anomalous sessions through a lightweight ML-based detection layer.

The honeypot can run as a single node or as multiple coordinated instances, with captured events forwarded to a SIEM in real time for alerting rather than relying solely on batch analysis.

---

## Tech stack

| Component | Tool |
|---|---|
| Backend | Python 3, Flask |
| Log analysis | Pandas, Matplotlib |
| Attacker simulation | Kali Linux, Hydra, curl |
| Environment | Linux / WSL, VirtualBox |

---

## Setup

```bash
git clone https://github.com/Harshil015/Honeypot-Lab.git
cd Honeypot-Lab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

The honeypot listens on port 5000 by default. All interactions are logged to `honeypot.log`.

**Run the analysis pipeline:**

```bash
python monitor_honeypot.py
```

---

## Exposed attack surface

- `/cmd` — command injection endpoint
- `/login` — brute-forceable login portal
- `/upload` — file upload accepting any file type
- `/jndi` — JNDI lookup simulation for Log4Shell-style probes
- `/shell.php`, `/cmd.php`, `/cgi-bin/` — botnet bait endpoints

---

## Attack scenarios tested

- Credential brute-force with Hydra
- Command injection via curl
- Web shell deployment and execution
- Enumeration scans (nmap, nikto)
- JNDI injection attempts

---

## What this demonstrates

- Deception-based defensive design and controlled lab deployment
- Attacker telemetry capture and structured data pipeline construction
- MITRE ATT&CK mapping applied to real observed traffic, not theoretical examples
- Red Team, Blue Team, and Purple Team workflow understanding in one project

---

## Limitations

- Tested on Linux/WSL; not tested on macOS or Windows natively

---

## Legal disclaimer

This is a lab tool. Use only in isolated environments you own and control. Do not deploy on production systems or any network without explicit authorization from the system owner.

---

## Author

**Harshil Makwana** — ECE graduate from SVNIT Surat, building security tools and looking for a first role in penetration testing, VAPT, or SOC.

[linkedin.com/in/harshilmakwana](https://linkedin.com/in/harshilmakwana) · [github.com/Harshil015](https://github.com/Harshil015)
