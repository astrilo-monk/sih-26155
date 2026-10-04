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


def earlier_scans(before: str, exclude: str, limit: int = 200) -> list[dict]:
    """Archived scan responses created before ``before`` (ISO time), newest first, without ``exclude``."""
    # ponytail: reads the last `limit` responses whole; index hostnames in a column if the archive grows large
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT response FROM scans WHERE created_at < ? AND scan_id <> ? ORDER BY created_at DESC LIMIT ?",
                (before, exclude, limit),
            ).fetchall()
    except Exception as e:
        logger.warning("Scan archive unavailable: %s", e)
        return []
    return [json.loads(row["response"]) for row in rows]
