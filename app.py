from flask import Flask, request, jsonify
import logging
import os
import subprocess
import shlex  # not strictly needed now but ok to keep

LOGFILE = os.path.join(os.path.dirname(__file__), "honeypot.log")

if not os.path.exists(LOGFILE):
    open(LOGFILE, "a").close()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[
        logging.FileHandler(LOGFILE),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

@app.route("/")
def index():
    return "Honeypot running (VULNERABLE mode). For lab use only."

@app.route("/vulnerable")
def vulnerable():
    """
    ACTUALLY vulnerable endpoint (for lab use only):
    - Takes ?cmd=<something> from the URL
    - Logs it with source IP & User-Agent
    - Executes the command on the server
    - Returns stdout and stderr to the client
    """
    cmd = request.args.get("cmd", "")
    src_ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "unknown")

    logging.info("HTTP_CMD src=%s ua=%s cmd=%s", src_ip, ua, cmd)

    if not cmd:
        return jsonify({"error": "no cmd parameter provided"}), 400

    try:
        proc = subprocess.run(
            cmd,
            shell=True,            # DANGEROUS – RCE
            capture_output=True,
            text=True,
            timeout=10
        )

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        rc = proc.returncode

        logging.info(
            "HTTP_CMD_RESULT src=%s rc=%s stdout=%s stderr=%s",
            src_ip, rc, stdout, stderr
        )

        return jsonify({
            "status": "executed",
            "source_ip": src_ip,
            "user_agent": ua,
            "cmd": cmd,
            "return_code": rc,
            "stdout": stdout,
            "stderr": stderr
        })

    except subprocess.TimeoutExpired:
        logging.warning("HTTP_CMD_TIMEOUT src=%s cmd=%s", src_ip, cmd)
        return jsonify({"status": "timeout", "cmd": cmd}), 504

    except Exception as e:
        logging.exception("HTTP_CMD_ERROR src=%s cmd=%s error=%s", src_ip, cmd, e)
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/login", methods=["GET", "POST"])
def fake_login():
    src_ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "unknown")

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Log login attempt
        logging.info(f"LOGIN_ATTEMPT src={src_ip} ua={ua} user={username} pass={password}")

        return jsonify({"status": "failed", "message": "Invalid username or password"}), 401

    # GET request → show fake login HTML page
    return """
    <html>
        <body>
            <h2>Login Portal</h2>
            <form action="/login" method="post">
                Username: <input name="username"><br>
                Password: <input name="password" type="password"><br>
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """


@app.route("/upload", methods=["POST"])
def fake_upload():
    src_ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "unknown")

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    filename = file.filename

    save_path = os.path.join(os.path.dirname(__file__), "uploads")
    os.makedirs(save_path, exist_ok=True)

    file_path = os.path.join(save_path, filename)
    file.save(file_path)

    file_size = os.path.getsize(file_path)

    logging.info(
        f"UPLOAD src={src_ip} ua={ua} filename={filename} size={file_size}"
    )

    return jsonify({"status": "uploaded", "filename": filename, "size": file_size})


@app.route("/api/admin", methods=["POST", "GET"])
def admin_api():
    src_ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "unknown")
    body = request.get_data(as_text=True)

    logging.info(f"ADMIN_API_ATTEMPT src={src_ip} ua={ua} body={body}")

    return jsonify({"error": "admin access denied"}), 403


@app.route("/etc/passwd")
def fake_passwd():
    logging.info(f"FAKE_FILE_READ src={request.remote_addr} file=/etc/passwd")
    return """
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    """, 200


@app.route("/proc/version")
def fake_proc_version():
    logging.info(f"FAKE_FILE_READ src={request.remote_addr} file=/proc/version")
    return "Linux version 5.15.0 (gcc version 11.2.0) #1 SMP", 200


@app.route("/server-status")
def fake_server_status():
    logging.info(f"SERVER_STATUS src={request.remote_addr}")
    return "Server running. Active connections: 4", 200


# ------------------ Botnet / scanner bait endpoints ------------------

from flask import Response

def enrich_src():
    return request.remote_addr or "unknown", request.headers.get("User-Agent", "unknown")

# 1) CGI-bin style directory (GET shows fake index, POST logs form data)
@app.route("/cgi-bin/", methods=["GET","POST"])
def cgi_bin():
    src, ua = enrich_src()
    if request.method == "POST":
        body = request.get_data(as_text=True)
        logging.info("CGI_POST src=%s ua=%s body=%s", src, ua, body)
        return jsonify({"status":"ok","note":"script executed (simulated)"}), 200
    logging.info("CGI_GET src=%s ua=%s", src, ua)
    return """
    <html><body>
    <h3>CGI Directory</h3>
    <p>This is a CGI-bin index. You may POST commands here.</p>
    <form method="post">
      cmd: <input name="cmd"><input type="submit">
    </form>
    </body></html>
    """

# 2) Shell-like endpoints — common filename bait
SHELL_PATHS = ["/shell","/sh","/bin/sh","/bash","/shell.php","/cmd.php","/upload.php"]

def make_shell_handler(path):
    # bind path into the handler via default arg to avoid late-binding issues
    def handler(path=path):
        src, ua = enrich_src()
        if request.method == "POST":
            # handle file upload like earlier
            if "file" in request.files:
                f = request.files["file"]
                fname = f.filename or "unknown"
                save_path = os.path.join(os.path.dirname(__file__), "uploads")
                os.makedirs(save_path, exist_ok=True)
                dest = os.path.join(save_path, fname)
                f.save(dest)
                size = os.path.getsize(dest)
                logging.info("WEBSHELL_UPLOAD src=%s ua=%s path=%s filename=%s size=%s",
                             src, ua, path, fname, size)
                return jsonify({"status":"uploaded","filename":fname})

            payload = request.get_data(as_text=True)
            logging.info("WEBSHELL_POST src=%s ua=%s path=%s payload=%s", src, ua, path, payload)
            return jsonify({"out": f"Simulated shell received payload ({len(payload)} bytes)"}), 200

        # GET
        logging.info("WEBSHELL_GET src=%s ua=%s path=%s", src, ua, path)
        return Response(f"<html><body><h2>Shell emulator: {path}</h2><p>Usage: POST data or upload a file.</p></body></html>", mimetype="text/html")
    return handler

# Register each route with a unique endpoint name
for p in SHELL_PATHS:
    endpoint_name = "shell_emulator_" + p.replace("/", "_").strip("_")
    app.add_url_rule(p, endpoint=endpoint_name, view_func=make_shell_handler(p), methods=["GET", "POST"])


# 3) Log4Shell style bait endpoint – catch any LDAP/JNDI attempts in headers/body
@app.route("/jndi", methods=["GET","POST"])
def jndi_bait():
    src, ua = enrich_src()
    body = request.get_data(as_text=True)

    # Flatten headers safely as strings
    headers = {str(k): str(v) for k, v in request.headers.items()}

    # Log the dangerous content
    logging.info("JNDI_BAIT src=%s ua=%s headers=%s body=%s", src, ua, headers, body)

    # Return a simple OK
    return jsonify({"status":"ok", "received": True}), 200

# 4) Headers echo endpoint: great to see scanner headers (X-Api-Version, X-My-Header, Referer, etc.)
@app.route("/headers", methods=["GET"])
def headers_echo():
    src, ua = enrich_src()
    headers = {str(k): str(v) for k, v in request.headers.items()}

    logging.info("HEADERS_ECHO src=%s ua=%s headers=%s", src, ua, headers)

    return jsonify({"headers": headers}), 200

# 5) Common CGI/old exploits bait (phpmyadmin, manager/html)
@app.route("/phpmyadmin/", methods=["GET","POST"])
def phpmyadmin_bait():
    src, ua = enrich_src()
    payload = request.get_data(as_text=True)
    logging.info("PHPMYADMIN_BAIT src=%s ua=%s payload=%s", src, ua, payload)
    return Response("<html><body><h2>phpMyAdmin</h2><p>Access denied.</p></body></html>", mimetype="text/html"), 403

@app.route("/manager/html", methods=["GET","POST"])
def tomcat_manager_bait():
    src, ua = enrich_src()
    logging.info("TOMCAT_MGR_BAIT src=%s ua=%s body=%s", src, ua, request.get_data(as_text=True))
    return Response("<html><body><h2>Tomcat Manager</h2></body></html>", mimetype="text/html"), 401


if __name__ == "__main__":
    # bind only to localhost for safety in WSL
    app.run(host="0.0.0.0", port=8080, debug=False)
