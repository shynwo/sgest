"""Blueprints Flask Sgest."""
from __future__ import annotations

from flask import Flask


def register_blueprints(app: Flask) -> None:
    from . import auth, catalog_public, main, stock, system, tools, webhooks

    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)
    app.register_blueprint(tools.bp)
    app.register_blueprint(catalog_public.bp)
    app.register_blueprint(system.bp)
    app.register_blueprint(stock.bp)
    app.register_blueprint(webhooks.bp)
