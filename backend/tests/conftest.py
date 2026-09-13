"""
Shared pytest fixtures.

Every test gets its own empty learned-mapping database so tests never read
or pollute the real ``backend/data/adaptive.db``.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def isolated_adaptive_db(tmp_path, monkeypatch):
    import app.config as app_config

    db_path = tmp_path / "adaptive.db"
    monkeypatch.setattr(app_config.settings, "adaptive_db_path", db_path)
    return db_path


@pytest.fixture(autouse=True)
def no_real_ai_judge(monkeypatch):
    """The AI judge never reaches the provider in tests (a dev .env may hold real keys); tests patch it to answer."""
    from app.ai.client import ERROR_UNAVAILABLE, StructuredResponse

    monkeypatch.setattr("app.ai.judge.request_structured", lambda **_: StructuredResponse(error=ERROR_UNAVAILABLE))
