"""Application factory Sgest."""
from __future__ import annotations

import os
import time
from datetime import timedelta
from pathlib import Path

from flask import Flask


def create_app() -> Flask:
    root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(root / "templates"),
        static_folder=str(root / "static"),
    )
    app.secret_key = os.getenv("SGEST_SECRET_KEY") or "dev-sgest-key-change-me"
    app.config["ASSET_VER"] = int(time.time())
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = str(os.getenv("SGEST_COOKIE_SECURE", "0")).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

    from . import services as svc

    app.before_request(svc.security_gate)
    app.after_request(svc.apply_security_headers)
    app.context_processor(svc.inject_asset_ver)
    app.errorhandler(404)(svc.not_found)
    app.errorhandler(500)(svc.server_error)

    from .routes import register_routes

    register_routes(app)

    return app
