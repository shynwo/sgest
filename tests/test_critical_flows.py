"""Flux critiques : santé publique, auth, garde API, backups JSON."""
from __future__ import annotations


def test_ping_public_json(client):
    r = client.get("/ping")
    assert r.status_code == 200
    data = r.get_json()
    assert data.get("ok") is True
    assert "t" in data


def test_login_get_ok(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert b"Connexion" in r.data or b"connexion" in r.data.lower()


def test_dashboard_redirects_unauthenticated(client):
    r = client.get("/")
    assert r.status_code in (302, 303)
    assert "/login" in r.headers.get("Location", "")


def test_api_alerts_requires_auth(client):
    r = client.get("/api/alerts/count", headers={"Accept": "application/json"})
    assert r.status_code == 401
    assert r.get_json().get("error") == "auth_required"


def test_api_backups_requires_auth(client):
    r = client.get("/api/backups", headers={"Accept": "application/json"})
    assert r.status_code == 401
