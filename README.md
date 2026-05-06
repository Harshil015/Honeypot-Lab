# Honeypot Lab
---

Red • Blue • Purple Team Cybersecurity Project
A custom-built Python/Flask honeypot that simulates real-world web vulnerabilities to capture attacker behavior, analyze payloads, and practice detection engineering.

---
# 📌 Overview

This project is a deception-based web honeypot designed to emulate vulnerable web services and attract attackers in a controlled lab environment.Instead of blocking attacks, this system intentionally
exposes realistic vulnerabilities and logs attacker interactions for research and learning. It allows hands-on experience in:
    1. Red Team exploitation
    2. Blue Team monitoring
    3. Purple Team feedback cycles
    4. Threat hunting & detection engineering
    5. Attacker behavior analysis

---

# 🎯 Project Goals

A. Simulate common web attack vectors safely
B. Capture attacker telemetry
C. Study attacker tactics & payloads
D. Build detection logic from real attacks
E. Understand MITRE ATT&CK techniques in practice

---

# 🔥 Features:

🟥 Offensive Simulation

1. Remote Command Execution (RCE) endpoint
    2. Brute-forceable login portal
    3. Webshell & malware upload traps
    4. Botnet bait endpoints (/shell.php, /cmd.php, /cgi-bin)
    5. Log4Shell-style JNDI payload capture

🟦 Defensive Visibility

1. Full request logging
2. Structured JSON-lines event logging
3. SQLite event persistence
4. GeoIP enrichment for country, city, ISP, and ASN
5. IP & User-Agent capture
6. Command execution logging
7. File upload tracking
8. Brute-force detection patterns

🟪 Purple Team Workflow

1. Attack → Log → Analyze → Improve detection
2. Detection tuning based on real payloads
3. MITRE ATT&CK mapping

---

# 🧰 Tech Stack

| Category            | Tools         |
| ------------------- | ------------- |
| Backend             | Python, Flask, SQLite |
| Environment         | Linux / WSL   |
| Attacker Simulation | Kali Linux    |
| Virtualization      | VirtualBox    |
| Version Control     | Git, GitHub   |

---

# 🧪 Example Attack Scenarios Tested

1. Credential brute-force with Hydra
2. Command injection via curl
3. Webshell deployment
4. Enumeration scans
5. JNDI injection attempts

---

# 📊 Skills Demonstrated

Red Team Testing
Blue Team Log Analysis
Purple Team Methodology
Detection Engineering
Threat Hunting
Deception Technology
Secure Lab Deployment

---

# 🚀 How to Run
    
    git clone https://github.com/YOUR_USERNAME/Honeypot-Lab.git
    cd Honeypot-Lab
    
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

    # Optional: execute captured commands in the lab VM. Default is capture-only.
    export HONEYPOT_ENABLE_RCE_EXECUTION=false
    python app.py

---

# ⚙️ Configuration

The application reads toggle-able settings from environment variables in `config.py`:

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `HONEYPOT_ENABLE_RCE_EXECUTION` | `false` | Enables real command execution on `/vulnerable` for isolated lab use only. |
| `HONEYPOT_UPLOAD_DIR` | `uploads/` | Directory for captured uploaded files and webshell bait uploads. |
| `HONEYPOT_LOG_LEVEL` | `INFO` | Logging threshold for structured JSON events. |
| `HONEYPOT_LOG_FILE` | `honeypot.log` | JSON-lines event log destination. |
| `HONEYPOT_DATABASE_PATH` | `db/events.db` | SQLite database path for persisted events. |
| `HONEYPOT_GEOIP_ENABLED` | `true` | Enables ip-api.com GeoIP enrichment for public source IPs. |

# 🧾 Event Storage

Each incoming request is GeoIP-enriched before routing. Every captured event is written as structured JSON to `honeypot.log` and persisted in SQLite at `db/events.db`. The local SQLite `events` table stores the event type, severity, source IP, User-Agent, payload, timestamp, GeoIP country/city/ISP/ASN metadata, and MITRE ATT&CK technique information.

Run the live monitor to tail structured events:

    python monitor_honeypot.py

---

# 👨‍💻 Author

Harshil Makwana

Cybersecurity Enthusiast | Red • Blue • Purple Team Learner

---

# ⭐ Why This Project Stands Out

This is not just a script — it is a hands-on security lab demonstrating:
1. Offensive security understanding
2. Defensive detection capability
3. Real attack simulation
4. Practical SOC-style analysis
5. Deception-based security thinking
This project reflects real-world cybersecurity workflows used by defenders and threat researchers.

---

# 📈 Future Improvements

SIEM integration
Automated detection alerts
Malware sandboxing
Multi-node honeypot deployment
ML-based anomaly detection

---

# 🤝 Contributions

Suggestions and improvements are welcome!
