"""
Shared pytest fixtures.

Every test gets its own empty learned-mapping database so tests never read
or pollute the real ``backend/data/adaptive.db``.

"Empty" includes the shipped seed recognizers (``app.facts.seed``): a test that asserts what the
generic engine works out on its own must not have seed knowledge answering for it. Tests about seed
knowledge ask for it with the ``seeded_adaptive_db`` fixture, which is the production default.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def isolated_adaptive_db(tmp_path, monkeypatch):
    import app.config as app_config

    from app.db import database

    db_path = tmp_path / "adaptive.db"
    monkeypatch.setattr(app_config.settings, "adaptive_db_path", db_path)
    # a dev .env may point at a real Postgres: tests always use their own SQLite file
    monkeypatch.setattr(app_config.settings, "database_url", "")
    # and a dev .env API key must not lock the test client out
    monkeypatch.setattr(app_config.settings, "api_key", "")
    # nor dev Supabase settings switch accounts on: tests about accounts turn them on themselves
    monkeypatch.setattr(app_config.settings, "supabase_url", "")
    # marking the path as already seeded is what keeps the shipped recognizers out
    monkeypatch.setattr(database, "_SEEDED", {db_path})
    yield db_path


@pytest.fixture
def seeded_adaptive_db(isolated_adaptive_db, monkeypatch):
    """The isolated database as a fresh deployment sees it: shipped seed recognizers loaded."""
    from app.db import database

    monkeypatch.setattr(database, "_SEEDED", set())
    database.init_db(isolated_adaptive_db)
    return isolated_adaptive_db


@pytest.fixture(autouse=True)
def no_real_ai_judge(monkeypatch):
    """The AI judge never reaches the provider in tests (a dev .env may hold real keys); tests patch it to answer."""
    from app.ai.client import ERROR_UNAVAILABLE, StructuredResponse

    monkeypatch.setattr("app.ai.judge.request_structured", lambda **_: StructuredResponse(error=ERROR_UNAVAILABLE))
