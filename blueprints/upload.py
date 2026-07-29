"""File upload capture."""

from flask import Blueprint, request
from datetime import datetime, timezone
from werkzeug.utils import secure_filename
from extensions import save_event
from services.event_logger import log_event
from services.ioc_extractor import extract_iocs
import logging
import os

upload_bp = Blueprint("upload", __name__)

# issue D7: cap how much of an uploaded file gets scanned for IOCs
# in-memory. The full file is still saved to disk regardless of this cap.
IOC_SCAN_MAX_BYTES = 1 * 1024 * 1024  # 1 MB


def _unique_filepath(directory: str, filename: str) -> str:
    """Return a path guaranteed not to collide with an existing file,
    appending a timestamp before the extension if one already exists
    (issue B3 -- uploading the same filename twice used to silently
    overwrite/truncate the first attacker's captured file).
    """
    filepath = os.path.join(directory, filename)
    if not os.path.exists(filepath):
        return filepath
    stem, ext = os.path.splitext(filename)
    timestamped = f"{stem}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}{ext}"
    return os.path.join(directory, timestamped)


@upload_bp.route("/upload", methods=["POST"])
def upload_file():
    app = upload_bp.app
    if "file" not in request.files:
        return "No file provided", 400

    file = request.files["file"]
    # issue B2: secure_filename() can reduce a name made only of unsafe
    # characters (e.g. "???.php" -> stripped further, or a name of only
    # symbols) down to "" -- os.path.join(dir, "") then resolves to the
    # directory itself, and file.save() on that raises IsADirectoryError,
    # crashing the request before the event is logged. file.filename can
    # also be None in some edge cases, which secure_filename() itself
    # can't accept, so that's guarded too.
    filename = secure_filename(file.filename or "")
    if not filename:
        filename = f"upload_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}.bin"

    filepath = _unique_filepath(app.config["UPLOAD_DIR"], filename)
    saved_filename = os.path.basename(filepath)

    # Save file for later analysis. Never executed anywhere in this app.
    file.save(filepath)

    # issue D7: also scan the actual file *contents* for IOCs, not just
    # the filename -- a webshell's body is far more likely to contain a
    # callback IP/URL than its filename is. Best-effort: unreadable or
    # binary content just means no IOCs are found; it must never fail the
    # upload itself.
    file_iocs = {"ips": [], "urls": [], "hashes": []}
    try:
        with open(filepath, "rb") as f:
            content_bytes = f.read(IOC_SCAN_MAX_BYTES)
        file_iocs = extract_iocs(content_bytes.decode("utf-8", errors="ignore"))
    except OSError:
        pass

    logger = logging.getLogger("honeypot.events")
    event_data = log_event(
        logger, "WEBSHELL_UPLOAD", "HIGH", "T1505.003", "Persistence",
        payload=saved_filename,
        details={"saved_to": filepath, "original_filename": file.filename, "content_iocs": file_iocs},
    )
    save_event(event_data)

    return "File uploaded successfully", 200
