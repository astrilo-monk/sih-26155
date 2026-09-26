"""
Tamper-evident audit ledger: an append-only, hash-chained record of what NetAuditAI decided and produced.

Every scan, taught recognizer, confirmed or rejected candidate fix and generated report appends one entry:

    hash = SHA-256(seq, at, kind, subject, content_hash, prev_hash)

``content_hash`` is the SHA-256 of the redacted artefact (the scan response the browser saw, the recognizer's
template, the PDF bytes): never a secret, never the configuration. Each entry carries the previous entry's hash,
so changing, deleting or reordering any stored entry breaks every hash after it, and ``verify`` names the first
entry that no longer checks out. A PDF can be checked against the ledger by its bytes.

It is a hash chain in the project's own database, not a distributed blockchain: it proves the record was not
edited after the fact, as long as the latest hash is kept somewhere else (the PDF footer prints it).
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from app.db.database import get_connection

logger = logging.getLogger(__name__)

GENESIS = "0" * 64
KINDS = ("scan", "recognizer", "candidate", "report")


def digest(content) -> str:
    """SHA-256 of bytes, text, or a JSON-able value (canonical: sorted keys, no whitespace)."""
    if not isinstance(content, (bytes, str)):
        content = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
    if isinstance(content, str):
        content = content.encode()
    return hashlib.sha256(content).hexdigest()


def _entry_hash(seq: int, at: str, kind: str, subject: str, content_hash: str, prev_hash: str) -> str:
    return digest([seq, at, kind, subject, content_hash, prev_hash])


def append(kind: str, subject: str, content) -> Optional[dict]:
    """Record one event. A ledger failure is logged and never fails the action it records."""
    content_hash = digest(content)
    for _ in range(3):  # ponytail: retry on a concurrent writer taking the same seq; a sequence would remove it
        try:
            with get_connection() as conn:
                head = conn.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
                seq, prev = (head["seq"] + 1, head["hash"]) if head else (1, GENESIS)
                at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                entry = dict(seq=seq, at=at, kind=kind, subject=subject, content_hash=content_hash, prev_hash=prev,
                             hash=_entry_hash(seq, at, kind, subject, content_hash, prev))
                conn.execute("INSERT INTO ledger (seq, at, kind, subject, content_hash, prev_hash, hash) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(entry.values()))
            return entry
        except Exception as e:
            error = e
    logger.warning("Ledger entry for %s %s not recorded: %s", kind, subject, error)
    return None


def entries(limit: int = 100) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute("SELECT seq, at, kind, subject, content_hash, prev_hash, hash FROM ledger "
                            "ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def verify() -> dict:
    """Recompute the whole chain. ``ok`` False names the first entry that no longer checks out, and why."""
    with get_connection() as conn:
        rows = [dict(r) for r in conn.execute("SELECT seq, at, kind, subject, content_hash, prev_hash, hash "
                                              "FROM ledger ORDER BY seq").fetchall()]
    prev, expected_seq = GENESIS, 1
    for row in rows:
        problem = None
        if row["seq"] != expected_seq:
            problem = f"entry #{expected_seq} is missing"
        elif row["prev_hash"] != prev:
            problem = "it does not follow the entry before it"
        elif row["hash"] != _entry_hash(row["seq"], row["at"], row["kind"], row["subject"],
                                        row["content_hash"], row["prev_hash"]):
            problem = "its content was changed after it was recorded"
        if problem:
            return {"ok": False, "entries": len(rows), "broken_at": row["seq"], "reason": problem,
                    "head": rows[-1]["hash"]}
        prev, expected_seq = row["hash"], row["seq"] + 1
    return {"ok": True, "entries": len(rows), "broken_at": None, "reason": None, "head": prev}


def latest(kind: str, subject: str) -> Optional[dict]:
    """The most recent entry of ``kind`` about ``subject``, or None (also when the store is unavailable)."""
    try:
        with get_connection() as conn:
            row = conn.execute("SELECT seq, at, kind, subject, content_hash, prev_hash, hash FROM ledger "
                               "WHERE kind = ? AND subject = ? ORDER BY seq DESC LIMIT 1", (kind, subject)).fetchone()
    except Exception as e:
        logger.warning("Ledger unavailable: %s", e)
        return None
    return dict(row) if row else None


def find(content_hash: str, kind: Optional[str] = None) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute("SELECT seq, at, kind, subject, content_hash, prev_hash, hash FROM ledger "
                           "WHERE content_hash = ? ORDER BY seq DESC LIMIT 1", (content_hash,)).fetchone()
    return dict(row) if row and (kind is None or row["kind"] == kind) else None
