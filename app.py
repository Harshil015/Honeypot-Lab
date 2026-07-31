"""Flask application factory for the Honeypot Lab."""

from __future__ import annotations
import logging
import os
from pathlib import Path
from flask import Flask
from blueprints.bait import bait_bp
from blueprints.login import login_bp
from blueprints.rce import rce_bp
from blueprints.upload import upload_bp
from blueprints.jndi import jndi_bp
from config import Config
from extensions import close_db_connection, init_database
from services.event_logger import JSONEventFormatter


def configure_logging(app: Flask) -> None:
    log_file = Path(app.config["LOG_FILE"])
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.touch(exist_ok=True)

    logger = logging.getLogger("honeypot.events")
    logger.setLevel(getattr(logging, app.config["LOG_LEVEL"], logging.INFO))
    logger.propagate = False
    logger.handlers.clear()

    formatter = JSONEventFormatter()
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Register blueprints to app context for DB access
    bait_bp.app = app
    login_bp.app = app
    rce_bp.app = app
    upload_bp.app = app
    jndi_bp.app = app

    Path(app.config["DB_DIR"]).mkdir(parents=True, exist_ok=True)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    configure_logging(app)
    init_database(app)
    app.teardown_appcontext(close_db_connection)
    app.register_blueprint(bait_bp)
    app.register_blueprint(rce_bp)
    app.register_blueprint(login_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(jndi_bp)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
