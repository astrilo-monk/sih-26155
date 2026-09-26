"""The audit ledger: every scan and report is recorded, a report PDF can be checked, and any edit is caught."""

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app import ledger
from app.main import app

CISCO = (Path(__file__).resolve().parents[2] / "demo-sih" / "cisco_edge_vulnerable.cfg").read_bytes()


def _scan(client):
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        return client.post("/api/scan", files=[("files", ("c.cfg", CISCO, "text/plain"))]).json()["scan_id"]


def test_a_scan_and_its_report_are_recorded_and_the_pdf_verifies(seeded_adaptive_db):
    client = TestClient(app)
    scan_id = _scan(client)
    pdf = client.post("/api/report", json={"scan_id": scan_id}).content
    kinds = [(e["kind"], e["subject"]) for e in client.get("/api/ledger").json()["entries"]]
    assert kinds[:2] == [("report", f"{scan_id}/0"), ("scan", scan_id)]

    checked = client.post("/api/ledger/verify-report", files={"file": ("r.pdf", pdf, "application/pdf")}).json()
    assert checked["match"] and checked["entry"]["kind"] == "report" and checked["chain"]["ok"]
    forged = pdf[:200] + bytes([pdf[200] ^ 1]) + pdf[201:]  # one bit changed
    assert forged != pdf
    assert not client.post("/api/ledger/verify-report", files={"file": ("r.pdf", forged, "application/pdf")}).json()["match"]


def test_the_report_names_its_scan_ledger_entry(seeded_adaptive_db):
    client = TestClient(app)
    scan_id = _scan(client)
    entry = ledger.latest("scan", scan_id)
    with patch("app.api.routes.report.device_report_pdf", wraps=__import__("app.reporting.report",
               fromlist=["device_report_pdf"]).device_report_pdf) as build:
        client.post("/api/report", json={"scan_id": scan_id})
    assert build.call_args.kwargs["ledger_entry"]["seq"] == entry["seq"]


def test_any_edit_or_deletion_breaks_the_chain_at_that_entry(seeded_adaptive_db):
    for i in range(4):
        ledger.append("scan", f"scan-{i}", {"posture": i})
    assert ledger.verify()["ok"]
    with sqlite3.connect(seeded_adaptive_db) as db:
        db.execute("UPDATE ledger SET content_hash = ? WHERE seq = 2", (ledger.digest({"posture": 100}),))
    broken = ledger.verify()
    assert broken == {**broken, "ok": False, "broken_at": 2, "reason": "its content was changed after it was recorded"}

    with sqlite3.connect(seeded_adaptive_db) as db:
        db.execute("DELETE FROM ledger WHERE seq = 2")
    assert ledger.verify()["reason"] == "entry #2 is missing"
