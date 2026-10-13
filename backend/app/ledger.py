"""
Tamper-evident audit ledger: an append-only, hash-chained record of what NetAuditAI decided and produced.

Every scan, taught recognizer, confirmed or rejected candidate fix and generated report appends one entry:

    hash = SHA-256(seq, at, kind, subject, content_hash, prev_hash)

``content_hash`` is the SHA-256 of the redacted artefact (the scan response the browser saw, the recognizer's
template, the PDF bytes): never a secret, never the configuration. Each entry carries the previous entry's hash,
so changing, deleting or reordering any stored entry breaks every hash after it, and ``verify`` names the first
entry that no longer checks out. A PDF can be checked against the ledger by its bytes.

Every entry is also signed with the deployment's Ed25519 key (its hash is what is signed). Without the
signature, someone able to write to the database could rewrite an entry and recompute every hash after it; with
it, they would also need the private key, which never leaves this host and is never in the repository. Anyone can
check an exported ledger offline with only the public key (``python -m app.cli ledger-verify``).

It is a signed hash chain in the project's own database, not a distributed blockchain: there is one writer and no
peers to agree with, so consensus would add weight and no integrity.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app import config as app_config
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


COLUMNS = "seq, at, kind, subject, content_hash, prev_hash, hash, key_id, signature"


def _load_key(env_key: str, path: str) -> Ed25519PrivateKey:
    if env_key:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(env_key))
    target = Path(path)
    if target.exists():
        key = serialization.load_pem_private_key(target.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{target} is not an Ed25519 private key")
        return key
    key = Ed25519PrivateKey.generate()
    target.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    # owner-only from the first byte: a key that was readable for a moment has been disclosed
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


@lru_cache(maxsize=4)
def _cached_key(env_key: str, path: str) -> Ed25519PrivateKey:
    return _load_key(env_key, path)


def signing_key() -> Ed25519PrivateKey:
    """This deployment's key: LEDGER_SIGNING_KEY (base64 of the 32-byte private key) when set, so a host whose
    disk is wiped keeps one key; otherwise a PEM file created on first use (settings.ledger_key_path)."""
    settings = app_config.settings
    return _cached_key(settings.ledger_signing_key, str(settings.ledger_key_path))


def public_hex(key: Ed25519PublicKey) -> str:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def key_id(public: str) -> str:
    """A short name for a public key (hex): the first 16 hex digits of its SHA-256."""
    return hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16]


def public_key() -> str:
    return public_hex(signing_key().public_key())


def trusted_keys() -> dict[str, str]:
    """key id -> public key (hex) of every key whose signatures this deployment accepts: its own, and earlier ones
    listed in LEDGER_TRUSTED_KEYS (comma-separated hex) after a key was rotated."""
    keys = [public_key(), *(k.strip() for k in app_config.settings.ledger_trusted_keys.split(",") if k.strip())]
    return {key_id(k): k for k in keys}


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
                entry.update(_signature(entry["hash"]))
                conn.execute(f"INSERT INTO ledger ({COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                             tuple(entry.values()))
            return entry
        except Exception as e:
            error = e
    logger.warning("Ledger entry for %s %s not recorded: %s", kind, subject, error)
    return None


def _signature(entry_hash: str) -> dict:
    """The deployment's signature over an entry hash. A key that cannot be loaded leaves the entry unsigned (and
    says so in the log): recording the event matters more than signing it, and verify counts unsigned entries."""
    try:
        key = signing_key()
    except Exception as e:
        logger.warning("Ledger signing key unavailable, entry left unsigned: %s", e)
        return {"key_id": None, "signature": None}
    return {"key_id": key_id(public_hex(key.public_key())), "signature": key.sign(entry_hash.encode()).hex()}


def entries(limit: int = 100) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(f"SELECT {COLUMNS} FROM ledger ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def all_entries() -> list[dict]:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(f"SELECT {COLUMNS} FROM ledger ORDER BY seq").fetchall()]


def verify_rows(rows: list[dict], trusted: dict[str, str]) -> dict:
    """Check a whole chain, oldest first, against the public keys ``trusted`` (key id -> hex). Needs nothing else,
    so an exported ledger can be checked on another machine. ``ok`` False names the first entry that does not
    check out, and why. Entries recorded before signing existed are counted as ``unsigned`` and leave
    ``fully_signed`` false; an unsigned entry after a signed one is tampering (its signature was stripped)."""
    prev, expected_seq, signed, unsigned = GENESIS, 1, 0, 0
    for row in rows:
        problem = None
        if row["seq"] != expected_seq:
            problem = f"entry #{expected_seq} is missing"
        elif row["prev_hash"] != prev:
            problem = "it does not follow the entry before it"
        elif row["hash"] != _entry_hash(row["seq"], row["at"], row["kind"], row["subject"],
                                        row["content_hash"], row["prev_hash"]):
            problem = "its content was changed after it was recorded"
        elif not row.get("signature"):
            # only entries from before signing existed may be unsigned: once one entry is signed, a later entry
            # without a signature had it stripped (a rewrite that hoped to pass as "legacy")
            if signed:
                problem = "it is unsigned but follows signed entries: its signature was removed"
            else:
                unsigned += 1
        elif row.get("key_id") not in trusted:
            problem = f"it is signed by key {row.get('key_id')}, which is not a trusted key"
        else:
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted[row["key_id"]])).verify(
                    bytes.fromhex(row["signature"]), row["hash"].encode())
                signed += 1
            except (InvalidSignature, ValueError):
                problem = "its signature does not match: it was rewritten without the signing key"
        if problem:
            return {"ok": False, "entries": len(rows), "broken_at": row["seq"], "reason": problem,
                    "head": rows[-1]["hash"], "signed": signed, "unsigned": unsigned, "fully_signed": False}
        prev, expected_seq = row["hash"], row["seq"] + 1
    # an unsigned entry is protected by the chain alone: whoever can write the database can rewrite it, so a
    # ledger is only fully trusted when every entry is signed
    return {"ok": True, "entries": len(rows), "broken_at": None, "reason": None, "head": prev,
            "signed": signed, "unsigned": unsigned, "fully_signed": unsigned == 0}


def verify() -> dict:
    """Recompute the whole chain and every signature against this deployment's trusted keys."""
    return {**verify_rows(all_entries(), trusted_keys()), "public_key": public_key(), "key_id": key_id(public_key())}


def export() -> dict:
    """Everything an offline check needs besides the trusted public key, which must come from elsewhere: a key
    inside the export proves nothing, since whoever rewrote the entries could have written it too."""
    return {"public_key": public_key(), "key_id": key_id(public_key()), "entries": all_entries()}


def latest(kind: str, subject: str) -> Optional[dict]:
    """The most recent entry of ``kind`` about ``subject``, or None (also when the store is unavailable)."""
    try:
        with get_connection() as conn:
            row = conn.execute(f"SELECT {COLUMNS} FROM ledger WHERE kind = ? AND subject = ? "
                               "ORDER BY seq DESC LIMIT 1", (kind, subject)).fetchone()
    except Exception as e:
        logger.warning("Ledger unavailable: %s", e)
        return None
    return dict(row) if row else None


def find(content_hash: str, kind: Optional[str] = None) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute(f"SELECT {COLUMNS} FROM ledger WHERE content_hash = ? ORDER BY seq DESC LIMIT 1",
                           (content_hash,)).fetchone()
    return dict(row) if row and (kind is None or row["kind"] == kind) else None
