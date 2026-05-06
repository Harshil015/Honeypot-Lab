"""Flask application factory for the Honeypot Lab."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, g

from blueprints.bait import bait_bp
from blueprints.login import login_bp
from blueprints.rce import rce_bp
from blueprints.upload import upload_bp
from config import Config
from extensions import close_db_connection, init_database
from services.event_logger import JSONEventFormatter, get_client_ip
from services.geoip import enrich_ip


def configure_logging(app: Flask) -> None:
    """Configure JSON-lines logging for structured honeypot telemetry."""
    log_file = Path(app.config["LOG_FILE"])
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.touch(exist_ok=True)

    logger = logging.getLogger("honeypot.events")
    logger.setLevel(getattr(logging, app.config["LOG_LEVEL"], logging.INFO))
    logger.propagate = False
    logger.handlers.clear()

    formatter = JSONEventFormatter()
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)


def create_app(config_class: type[Config] = Config) -> Flask:
    """Build and configure the Flask honeypot application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    Path(app.config["DB_DIR"]).mkdir(parents=True, exist_ok=True)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    configure_logging(app)
    init_database(app)
    app.teardown_appcontext(close_db_connection)

    @app.before_request
    def enrich_request_geoip() -> None:
        g.geoip = enrich_ip(get_client_ip())

    app.register_blueprint(bait_bp)
    app.register_blueprint(rce_bp)
    app.register_blueprint(login_bp)
    app.register_blueprint(upload_bp)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
