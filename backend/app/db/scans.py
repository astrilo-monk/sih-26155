"""
Scan history that survives a restart.

A scan lives in memory while it is worked on (``app.api.routes.scan._scan_store``): teaching, review and
remediation need the uploaded configuration. What is persisted is only what the browser already received -
the redacted scan response and the redacted remediation plans - so a past scan can be reopened and its PDF
downloaded after a restart, while no password, key or community string is ever stored. Acting on an archived
scan (teaching, fixing) needs the configuration again, so it has to be uploaded again.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from app.db.database import get_connection

logger = logging.getLogger(__name__)


def save_scan(scan_id: str, created_at: str, response: dict, plans: list[dict]) -> None:
    """Store (or replace) the archived copy of a scan. A store failure is logged: it never fails a scan."""
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO scans (scan_id, created_at, updated_at, response, plans) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (scan_id) DO UPDATE SET updated_at = excluded.updated_at, "
                "response = excluded.response, plans = excluded.plans",
                (scan_id, created_at, datetime.now(timezone.utc).isoformat(), json.dumps(response), json.dumps(plans)),
            )
    except Exception as e:
        logger.warning("Scan %s not archived: %s", scan_id, e)


def load_scan(scan_id: str) -> Optional[tuple[dict, list[dict]]]:
    """``(response, plans)`` of an archived scan, or None."""
    try:
        with get_connection() as conn:
            row = conn.execute("SELECT response, plans FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    except Exception as e:
        logger.warning("Scan archive unavailable: %s", e)
        return None
    return (json.loads(row["response"]), json.loads(row["plans"])) if row else None


def scan_exists(scan_id: str) -> bool:
    """Whether the archive holds this scan. Reads one value, not the scan: history asks this of every entry."""
    try:
        with get_connection() as conn:
            return conn.execute("SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)).fetchone() is not None
    except Exception as e:
        logger.warning("Scan archive unavailable: %s", e)
        return False


def _contains(key: str, value) -> str:
    """A LIKE pattern for ``"key": value`` as ``json.dumps`` writes it in a stored response."""
    text = f'"{key}": {json.dumps(value)}'
    # "!" escapes: a backslash means different things to SQLite and Postgres LIKE
    return "%" + text.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"


def earlier_scans(before: str, exclude: str, devices: list[dict], per_device: int = 3) -> list[dict]:
    """Archived scan responses created before ``before`` (ISO time) that may hold one of ``devices`` (same hostname
    and vendor), newest first, without ``exclude``.

    The database filters on the stored text, so only a few candidates per device leave it instead of the whole
    archive: on a hosted database every byte read is egress. Callers still match each device exactly.
    """
    found: dict[str, tuple[str, str]] = {}
    try:
        with get_connection() as conn:
            for device in devices:
                rows = conn.execute(
                    "SELECT scan_id, created_at, response FROM scans WHERE created_at < ? AND scan_id <> ? "
                    "AND response LIKE ? ESCAPE '!' AND response LIKE ? ESCAPE '!' "
                    "ORDER BY created_at DESC LIMIT ?",
                    (before, exclude, _contains("hostname", device.get("hostname")),
                     _contains("vendor", device.get("vendor")), per_device),
                ).fetchall()
                for row in rows:
                    found.setdefault(row["scan_id"], (row["created_at"], row["response"]))
    except Exception as e:
        logger.warning("Scan archive unavailable: %s", e)
        return []
    return [json.loads(response) for _, response in sorted(found.values(), reverse=True)]
