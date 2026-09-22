"""API_KEY: unset leaves every route open; set, /api requires a matching X-API-Key header."""

from fastapi.testclient import TestClient

import app.config as app_config
from app.main import app

client = TestClient(app)


def test_no_key_configured_needs_no_header():
    assert client.get("/api/assistant/status").status_code == 200


def test_configured_key_is_required_on_api_routes(monkeypatch):
    monkeypatch.setattr(app_config.settings, "api_key", "s3cret-key")
    assert client.get("/api/assistant/status").status_code == 401
    assert client.get("/api/assistant/status", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/assistant/status", headers={"X-API-Key": "s3cret-key"}).status_code == 200
    assert client.get("/health").status_code == 200
