"""
Signed audit ledger (``app.ledger``): every entry carries an Ed25519 signature over its hash, so rewriting an
entry and recomputing the chain after it is caught unless the private key was also taken. An export can be
checked offline with only the public key.
"""

import json

from fastapi.testclient import TestClient

from app import ledger
from app.cli import main as cli
from app.db.database import get_connection
from app.main import app


def _three():
    for n in range(3):
        ledger.append("scan", f"scan-{n}", {"n": n})


def test_every_entry_is_signed_and_verifies():
    _three()
    result = ledger.verify()
    assert result["ok"] and result["signed"] == 3 and result["unsigned"] == 0
    assert all(e["signature"] and e["key_id"] == result["key_id"] for e in ledger.entries())


def test_a_rewritten_chain_is_caught_by_its_signature():
    """The attack a plain hash chain cannot stop: change an entry, then recompute every hash after it."""
    _three()
    rows = ledger.all_entries()
    prev = rows[0]["hash"]
    with get_connection() as conn:
        for row in rows[1:]:
            subject = "forged" if row["seq"] == 2 else row["subject"]
            new = ledger._entry_hash(row["seq"], row["at"], row["kind"], subject, row["content_hash"], prev)
            conn.execute("UPDATE ledger SET subject = ?, prev_hash = ?, hash = ? WHERE seq = ?",
                         (subject, prev, new, row["seq"]))
            prev = new
    result = ledger.verify()
    assert not result["ok"] and result["broken_at"] == 2
    assert "signature" in result["reason"]


def test_an_entry_signed_by_another_key_is_not_trusted():
    _three()
    other = ledger.Ed25519PrivateKey.generate()
    row = ledger.all_entries()[1]
    with get_connection() as conn:
        conn.execute("UPDATE ledger SET key_id = ?, signature = ? WHERE seq = 2",
                     (ledger.key_id(ledger.public_hex(other.public_key())), other.sign(row["hash"].encode()).hex()))
    result = ledger.verify()
    assert not result["ok"] and "not a trusted key" in result["reason"]


def test_entries_from_before_signing_still_chain_and_are_counted():
    _three()
    with get_connection() as conn:
        conn.execute("UPDATE ledger SET key_id = NULL, signature = NULL WHERE seq = 1")
    result = ledger.verify()
    assert result["ok"] and result["unsigned"] == 1 and result["signed"] == 2 and not result["fully_signed"]


def test_a_stripped_signature_after_signed_entries_is_tampering():
    """Rewrite entry 2 and the chain after it, and drop their signatures hoping to pass as legacy entries."""
    _three()
    rows = ledger.all_entries()
    prev = rows[0]["hash"]
    with get_connection() as conn:
        for row in rows[1:]:
            new = ledger._entry_hash(row["seq"], row["at"], row["kind"], "forged", row["content_hash"], prev)
            conn.execute("UPDATE ledger SET subject = 'forged', prev_hash = ?, hash = ?, key_id = NULL, "
                         "signature = NULL WHERE seq = ?", (prev, new, row["seq"]))
            prev = new
    result = ledger.verify()
    assert not result["ok"] and result["broken_at"] == 2 and "signature was removed" in result["reason"]


def test_the_export_checks_offline_with_only_the_public_key(tmp_path, capsys):
    _three()
    client = TestClient(app)
    export = client.get("/api/ledger/export").json()
    public = client.get("/api/ledger/public-key").json()["public_key"]
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(export))
    assert cli(["ledger-verify", str(path), "--public-key", public]) == 0
    assert "intact: 3 entries, 3 signed" in capsys.readouterr().out

    export["entries"][0]["subject"] = "edited"
    path.write_text(json.dumps(export))
    assert cli(["ledger-verify", str(path), "--public-key", public]) == 1
    # a key that is not the deployment's: every signature fails to match
    stranger = ledger.public_hex(ledger.Ed25519PrivateKey.generate().public_key())
    path.write_text(json.dumps(client.get("/api/ledger/export").json()))
    assert cli(["ledger-verify", str(path), "--public-key", stranger]) == 1


def test_offline_check_refuses_unsigned_entries_unless_allowed(tmp_path, capsys):
    """Every entry unsigned: the chain holds, but nothing proves who wrote it."""
    _three()
    client = TestClient(app)
    export = client.get("/api/ledger/export").json()
    for entry in export["entries"]:
        entry["key_id"] = entry["signature"] = None
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(export))
    public = export["public_key"]
    assert cli(["ledger-verify", str(path), "--public-key", public]) == 1
    assert "NOT PROVEN" in capsys.readouterr().out
    assert cli(["ledger-verify", str(path), "--public-key", public, "--allow-unsigned"]) == 0


def test_the_key_file_is_created_once_and_reused(tmp_path, monkeypatch):
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "ledger_key_path", tmp_path / "k" / "key.pem")
    first = ledger.public_key()
    ledger._cached_key.cache_clear()
    assert ledger.public_key() == first
    assert (tmp_path / "k" / "key.pem").read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
