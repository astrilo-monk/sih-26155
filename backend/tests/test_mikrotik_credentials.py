"""
RouterOS: the default SNMP community renamed to ``public``, and local users with a password in the file.

Seed knowledge reads both (``data/seed_recognizers.json``); the password and a custom community string
are secrets, so neither may reach a stored recognizer, the scan response, the PDF or the ledger.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.db.mappings import MappingRepository
from app.main import app
from tests.test_pdf_report import text_of
from tests.test_seed_knowledge import _results

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "seed_dialects" / "routeros_credentials.rsc"
SECRETS = ("MtRoComm7", "MtAdminPw9", "MtBackupPw4")


def _text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_the_default_community_named_public_fails_and_the_password_is_plaintext(seeded_adaptive_db):
    results = _results(_text())
    assert results["MGMT-004"].status.value == "fail"
    assert 4 in results["MGMT-004"].evidence.line_numbers
    assert results["MGMT-005"].status.value == "fail"
    # each account stores its own password, so each is its own FAIL citing its own line
    from tests.test_seed_knowledge import _unknown, evaluate_controls
    cited = {n for r in evaluate_controls(_unknown(_text())) if r.control_id == "MGMT-005" and r.status.value == "fail"
             for n in r.evidence.line_numbers}
    assert {7, 9} <= cited


@pytest.mark.parametrize("line", [
    "/snmp community set [ find default=yes ] name=n0c-view",
    "/snmp community set [find default=yes] name=n0c-view",
    "/snmp community\nadd name=n0c-view",
])
def test_a_custom_community_name_passes(seeded_adaptive_db, line):
    results = _results(line + "\n")
    assert results["MGMT-004"].status.value == "pass"
    assert results["MGMT-011"].status.value == "fail"  # a community is still SNMPv1/v2c


@pytest.mark.parametrize("line", [
    "/user set ops password=x1 group=full",
    "/user set ops group=full password=x1",
    "/user add name=ops password=x1 group=read",
    "/user add name=ops group=read password=x1",
])
def test_every_user_form_states_a_plaintext_password(seeded_adaptive_db, line):
    assert _results(line + "\n")["MGMT-005"].status.value == "fail"


def test_no_secret_reaches_a_recognizer_the_scan_the_pdf_or_the_ledger(seeded_adaptive_db):
    stored = json.dumps([m.__dict__ for m in MappingRepository(seeded_adaptive_db).list_mappings()], default=str)
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        client = TestClient(app)
        scan = client.post("/api/scan", files=[("files", ("mt.rsc", _text(), "text/plain"))]).json()
        pdf = client.post("/api/report", json={"scan_id": scan["scan_id"]}).content
        ledger = client.get("/api/ledger").text
        report = text_of(client, scan["scan_id"])
    assert "MGMT-005" in report
    assert {r["control_id"]: r["status"] for r in scan["results"]}["MGMT-005"] == "fail"
    for secret in SECRETS:
        assert secret not in stored and secret not in json.dumps(scan) and secret not in ledger
        assert secret.encode() not in pdf and secret not in report
