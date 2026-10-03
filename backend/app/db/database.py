"""
Database connection handling and schema migrations: SQLite by default, Postgres when ``DATABASE_URL`` is set.

Migrations are applied in order and tracked with ``PRAGMA user_version`` (SQLite) or the
``schema_version`` table (Postgres), so an existing database is upgraded in place and a new one is
created from scratch. Connections are short-lived (one per repository operation), which keeps things
safe under FastAPI's threadpool without extra locking.

Callers write one SQL dialect: ``?`` placeholders and statements both engines run (``ON CONFLICT``,
``RETURNING``). The Postgres connection translates the placeholders.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

from app import config as app_config


MIGRATIONS: list[str] = [
    # v1 -learned mappings + reviewed-but-unmapped lines
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
    # v2 -recognizers (Phase 6): a mapping answers a security predicate. Field mappings keep their
    # columns until Phase 7 ends; their predicate is derived from FIELD_PREDICATES when read.
    """
    ALTER TABLE learned_mappings ADD COLUMN predicate TEXT;
    ALTER TABLE learned_mappings ADD COLUMN subject TEXT;
    ALTER TABLE learned_mappings ADD COLUMN scope_template TEXT;
    ALTER TABLE learned_mappings ADD COLUMN dialect_fingerprint TEXT;
    ALTER TABLE learned_mappings ADD COLUMN negatives TEXT NOT NULL DEFAULT '[]';
    """,
    # v3 -AI judge cache (Phase 7): proposals keyed by hash(prompt version + model + redacted prompt)
    """
    CREATE TABLE IF NOT EXISTS ai_judge_cache (
        key         TEXT PRIMARY KEY,
        response    TEXT NOT NULL,
        created_at  TEXT NOT NULL
    );
    """,
    # v4 -provenance of a mapping: 'seed' = shipped knowledge (backend/data/seed_recognizers.json),
    # 'runtime' = learned from an administrator. Seeding never touches a runtime row.
    """
    ALTER TABLE learned_mappings ADD COLUMN source TEXT NOT NULL DEFAULT 'runtime';
    """,
    # v5 -scan history: the redacted scan response and remediation plans, never the configuration
    """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id     TEXT PRIMARY KEY,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        response    TEXT NOT NULL,
        plans       TEXT NOT NULL DEFAULT '[]'
    );
    """,
    # v6 -tamper-evident audit ledger (app/ledger.py): hashes of redacted artefacts only
    """
    CREATE TABLE IF NOT EXISTS ledger (
        seq          INTEGER PRIMARY KEY,
        at           TEXT NOT NULL,
        kind         TEXT NOT NULL,
        subject      TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        prev_hash    TEXT NOT NULL,
        hash         TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_ledger_content ON ledger (content_hash);
    """,
    # v7 -owner of learned knowledge (app.auth): '' = shared (seeds, a local install), 'user:<id>' = a signed-in
    # account, 'guest:<id>' = one browser. A rejection is unique per owner, so the table is rebuilt.
    """
    ALTER TABLE learned_mappings ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';
    CREATE TABLE rejected_lines_v7 (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id    TEXT NOT NULL DEFAULT '',
        line_key    TEXT NOT NULL,
        raw_line    TEXT NOT NULL,
        vendor      TEXT,
        reason      TEXT,
        created_at  TEXT NOT NULL,
        UNIQUE (owner_id, line_key)
    );
    INSERT INTO rejected_lines_v7 (id, line_key, raw_line, vendor, reason, created_at)
        SELECT id, line_key, raw_line, vendor, reason, created_at FROM rejected_lines;
    DROP TABLE rejected_lines;
    ALTER TABLE rejected_lines_v7 RENAME TO rejected_lines;
    """,
]


# Postgres (Supabase): the same schema as SQLite migrations v1-v4 (then v5), in Postgres types. A later SQLite
# migration needs its Postgres counterpart appended here.
PG_MIGRATIONS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS learned_mappings (
        id                  BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
        concept             TEXT    NOT NULL,
        normalized_field    TEXT    NOT NULL,
        vendor              TEXT,
        command_pattern     TEXT    NOT NULL,
        extraction_method   TEXT    NOT NULL,
        expected_value_type TEXT    NOT NULL,
        constant_value      TEXT,
        confidence          DOUBLE PRECISION NOT NULL DEFAULT 1.0,
        confirmed           INTEGER NOT NULL DEFAULT 0,
        active              INTEGER NOT NULL DEFAULT 1,
        example_line        TEXT,
        created_at          TEXT    NOT NULL,
        updated_at          TEXT    NOT NULL,
        predicate           TEXT,
        subject             TEXT,
        scope_template      TEXT,
        dialect_fingerprint TEXT,
        negatives           TEXT    NOT NULL DEFAULT '[]',
        source              TEXT    NOT NULL DEFAULT 'runtime'
    );
    CREATE INDEX IF NOT EXISTS idx_learned_mappings_active ON learned_mappings (active, confirmed);
    CREATE TABLE IF NOT EXISTS rejected_lines (
        id          BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
        line_key    TEXT NOT NULL UNIQUE,
        raw_line    TEXT NOT NULL,
        vendor      TEXT,
        reason      TEXT,
        created_at  TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ai_judge_cache (
        key         TEXT PRIMARY KEY,
        response    TEXT NOT NULL,
        created_at  TEXT NOT NULL
    );
    """,
    # SQLite v5
    """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id     TEXT PRIMARY KEY,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        response    TEXT NOT NULL,
        plans       TEXT NOT NULL DEFAULT '[]'
    );
    """,
    # SQLite v6
    """
    CREATE TABLE IF NOT EXISTS ledger (
        seq          BIGINT PRIMARY KEY,
        at           TEXT NOT NULL,
        kind         TEXT NOT NULL,
        subject      TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        prev_hash    TEXT NOT NULL,
        hash         TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_ledger_content ON ledger (content_hash);
    """,
    # SQLite v7
    """
    ALTER TABLE learned_mappings ADD COLUMN IF NOT EXISTS owner_id TEXT NOT NULL DEFAULT '';
    ALTER TABLE rejected_lines ADD COLUMN IF NOT EXISTS owner_id TEXT NOT NULL DEFAULT '';
    ALTER TABLE rejected_lines DROP CONSTRAINT IF EXISTS rejected_lines_line_key_key;
    CREATE UNIQUE INDEX IF NOT EXISTS ux_rejected_lines_owner ON rejected_lines (owner_id, line_key);
    """,
    # Postgres only: the browser holds the Supabase anon key (sign-in), and with it anyone could read these tables
    # through Supabase's REST API. Row level security with no policy shuts that door; the backend connects as the
    # tables' owner, which RLS does not apply to.
    """
    ALTER TABLE learned_mappings ENABLE ROW LEVEL SECURITY;
    ALTER TABLE rejected_lines ENABLE ROW LEVEL SECURITY;
    ALTER TABLE ai_judge_cache ENABLE ROW LEVEL SECURITY;
    ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
    ALTER TABLE ledger ENABLE ROW LEVEL SECURITY;
    ALTER TABLE schema_version ENABLE ROW LEVEL SECURITY;
    """,
]


# Databases this process has already offered the shipped seed knowledge to (loading is idempotent
# anyway; this keeps it off the per-connection path).
_SEEDED: set[Path | str] = set()
# Postgres databases this process has already migrated: one version query per process, not per connection
_MIGRATED: set[str] = set()


def resolve_db_path(db_path: Path | str | None = None) -> Path:
    """Explicit path wins; otherwise read settings at call time (tests override it)."""
    return Path(db_path) if db_path is not None else Path(app_config.settings.adaptive_db_path)


def _database_url(db_path: Path | str | None) -> str:
    """The Postgres URL to use, or "" for SQLite. An explicit path always means SQLite."""
    return "" if db_path is not None else _encode_password((app_config.settings.database_url or "").strip())


def _encode_password(url: str) -> str:
    """Percent-encode a password pasted raw from a dashboard: an ``@`` in it would otherwise be read as the host.

    Only a URL with more than one ``@`` is touched, so an already-encoded password is never encoded twice.
    """
    scheme, sep, rest = url.partition("://")
    if not sep or rest.count("@") < 2:
        return url
    credentials, host = rest.rsplit("@", 1)
    user, _, password = credentials.partition(":")
    return f"{scheme}://{user}:{quote(password, safe='')}@{host}"


class _PgConnection:
    """A psycopg connection that takes the ``?`` placeholders and ``row["col"]`` access SQLite callers use."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql: str, params=()):
        return self._conn.execute(sql.replace("?", "%s"), params)


# One pool per URL: opening a connection to a hosted Postgres costs far more than a query
_POOLS: dict = {}


def _pg_pool(url: str):
    if url not in _POOLS:
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        # prepare_threshold=None: Supabase's transaction pooler cannot hold prepared statements.
        # check: a connection the server dropped while idle is replaced instead of failing a request.
        _POOLS[url] = ConnectionPool(
            url, min_size=1, max_size=4, open=True, check=ConnectionPool.check_connection,
            kwargs={"row_factory": dict_row, "prepare_threshold": None, "connect_timeout": 10},
        )
    return _POOLS[url]


def _init_pg(url: str) -> str:
    if url not in _MIGRATED:
        with _pg_pool(url).connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
            version = row["v"] or 0
            for index, script in enumerate(PG_MIGRATIONS[version:], start=version + 1):
                conn.execute(script)
                conn.execute("INSERT INTO schema_version (version) VALUES (%s)", (index,))
        _MIGRATED.add(url)
    if url not in _SEEDED:
        _SEEDED.add(url)
        from app.facts.seed import load_seed_recognizers

        load_seed_recognizers()
    return url


def init_db(db_path: Path | str | None = None) -> Path | str:
    """Create the database if needed and apply pending migrations."""
    url = _database_url(db_path)
    if url:
        return _init_pg(url)
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

    if path not in _SEEDED:
        # Marked before loading: the loader opens its own connection and lands back here.
        _SEEDED.add(path)
        from app.facts.seed import load_seed_recognizers

        load_seed_recognizers(path)
    return path


@contextmanager
def get_connection(db_path: Path | str | None = None) -> Iterator[sqlite3.Connection]:
    """Yield a migrated connection; commits on success, rolls back on error."""
    target = init_db(db_path)
    if isinstance(target, str):
        # the pool commits on success, rolls back on error and takes the connection back
        with _pg_pool(target).connection() as pg:
            yield _PgConnection(pg)
        return
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
