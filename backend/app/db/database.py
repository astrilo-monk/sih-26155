"""
SQLite connection handling and schema migrations.

Migrations are applied in order and tracked with ``PRAGMA user_version``,
so an existing database is upgraded in place and a new one is created
from scratch. Connections are short-lived (one per repository operation),
which keeps things safe under FastAPI's threadpool without extra locking.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app import config as app_config


MIGRATIONS: list[str] = [
    # v1 — learned mappings + reviewed-but-unmapped lines
    """
    CREATE TABLE IF NOT EXISTS learned_mappings (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        concept             TEXT    NOT NULL,
        normalized_field    TEXT    NOT NULL,
        vendor              TEXT,
        command_pattern     TEXT    NOT NULL,
        extraction_method   TEXT    NOT NULL,
        expected_value_type TEXT    NOT NULL,
        constant_value      TEXT,
        confidence          REAL    NOT NULL DEFAULT 1.0,
        confirmed           INTEGER NOT NULL DEFAULT 0,
        active              INTEGER NOT NULL DEFAULT 1,
        example_line        TEXT,
        created_at          TEXT    NOT NULL,
        updated_at          TEXT    NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_learned_mappings_active
        ON learned_mappings (active, confirmed);

    CREATE TABLE IF NOT EXISTS rejected_lines (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        line_key    TEXT NOT NULL UNIQUE,
        raw_line    TEXT NOT NULL,
        vendor      TEXT,
        reason      TEXT,
        created_at  TEXT NOT NULL
    );
    """,
    # v2 — recognizers (Phase 6): a mapping answers a security predicate. Field mappings keep their
    # columns until Phase 7 ends; their predicate is derived from FIELD_PREDICATES when read.
    """
    ALTER TABLE learned_mappings ADD COLUMN predicate TEXT;
    ALTER TABLE learned_mappings ADD COLUMN subject TEXT;
    ALTER TABLE learned_mappings ADD COLUMN scope_template TEXT;
    ALTER TABLE learned_mappings ADD COLUMN dialect_fingerprint TEXT;
    ALTER TABLE learned_mappings ADD COLUMN negatives TEXT NOT NULL DEFAULT '[]';
    """,
]


def resolve_db_path(db_path: Path | str | None = None) -> Path:
    """Explicit path wins; otherwise read settings at call time (tests override it)."""
    return Path(db_path) if db_path is not None else Path(app_config.settings.adaptive_db_path)


def init_db(db_path: Path | str | None = None) -> Path:
    """Create the database file if needed and apply pending migrations."""
    path = resolve_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        for index, script in enumerate(MIGRATIONS[version:], start=version + 1):
            conn.executescript(script)
            conn.execute(f"PRAGMA user_version = {index}")
        conn.commit()
    finally:
        conn.close()
    return path


@contextmanager
def get_connection(db_path: Path | str | None = None) -> Iterator[sqlite3.Connection]:
    """Yield a migrated connection; commits on success, rolls back on error."""
    path = init_db(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
