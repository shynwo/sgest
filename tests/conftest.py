"""Fixtures pytest pour Sgest."""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("SGEST_SECRET_KEY", "test-secret-key-for-ci")


@pytest.fixture
def app():
    from sgest.factory import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True)
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()
