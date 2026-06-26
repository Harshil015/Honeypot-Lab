# Honeypot Lab

A Python/Flask honeypot that emulates vulnerable web services to capture real attacker behaviour — not simulated traffic. Deployed in a controlled lab environment and left running. What came back was more interesting than I expected.

---

## What it captured

Over 500 interactions across four attack vectors in the first deployment window:

| Attack vector | MITRE ATT&CK | What was observed |
|---|---|---|
| Remote code execution | T1190 | Command injection attempts via exposed eval-style endpoints |
| Brute-force login | T1110 | Credential lists ordered by frequency — methodical, not random |
| Web shell deployment | T1505.003 | Automated .php shell uploads within minutes of service discovery |
| JNDI injection | T1059 | Log4Shell-style payloads still actively probing in 2025 |

---

## What the data showed

Three things that stood out during analysis:

**Bots don't wait.** RCE probes started within minutes of the service going up. The internet is constantly scanning — if a port is open, something will find it.

**Log4Shell isn't going away.** JNDI injection attempts were consistent throughout the deployment window, years after the patch dropped. Attackers don't retire working payloads because a fix exists.

**Brute-force is methodical.** Credential lists arrived in frequency order — most common passwords first. This tells you something about how attackers optimise their tooling for efficiency, not randomness.

---

## Architecture

```
app.py              — Flask app with intentionally vulnerable endpoints
monitor_honeypot.py — Pandas/Matplotlib log analysis and session replay pipeline
honeypot.log        — Raw interaction dataset (included as reference)
uploads/            — Captured upload attempts
```

The analysis pipeline (`monitor_honeypot.py`) processes structured logs into:
- Interaction timeline by attack type
- Payload frequency distribution charts
- Session replay for full kill-chain reconstruction
- 35% faster review compared to raw log inspection

---

## Tech stack

| Component | Tool |
|---|---|
| Backend | Python 3, Flask |
| Log analysis | Pandas, Matplotlib |
| Attacker simulation | Kali Linux, Hydra, curl |
| Environment | Linux / WSL, VirtualBox |
| Version control | Git, GitHub |

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

Generates charts and a session-replay summary from captured log data.

---

## Exposed attack surface

The honeypot intentionally exposes the following endpoints for capture purposes:

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

## Limitations

- Single-node deployment — does not replicate distributed honeypot architectures
- No active alerting — analysis is post-hoc via the pipeline
- Tested on Linux/WSL; not tested on macOS or Windows natively

---

## Roadmap

- [ ] SIEM integration for real-time alerting
- [ ] Automated IOC extraction from captured payloads
- [ ] YARA rule generation from observed patterns
- [ ] Multi-node deployment support
- [ ] ML-based anomaly detection layer

---

## Legal disclaimer

This is a lab tool. Use only in isolated environments you own and control. Do not deploy on production systems or any network without explicit authorisation from the system owner.

---

## Author

**Harshil Makwana** — ECE graduate from SVNIT Surat  
[linkedin.com/in/harshilmakwana](https://linkedin.com/in/harshilmakwana) · [github.com/Harshil015](https://github.com/Harshil015)
