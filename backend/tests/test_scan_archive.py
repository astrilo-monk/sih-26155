"""
Scan history survives a restart: a redacted copy of every scan is archived in the database.
A restart is simulated by emptying the in-memory store.
"""

import io

import pytest
from fastapi.testclient import TestClient

from app.api.routes import scan as scan_routes
from app.db.database import get_connection
from app.main import app

CISCO = """!
hostname ARCHIVE-01
!
enable password 0 SuperSecretEnable123
username admin privilege 15 password 0 AdminPassw0rdVal
snmp-server community TopSecretCommunity RW
!
line vty 0 4
 transport input telnet ssh
!
ip http server
!
"""
SECRETS = ("SuperSecretEnable123", "AdminPassw0rdVal", "TopSecretCommunity")


@pytest.fixture
def client(seeded_adaptive_db):
    return TestClient(app)


def _scan(client) -> dict:
    response = client.post("/api/scan", files={"files": ("r1.cfg", io.BytesIO(CISCO.encode()), "text/plain")})
    assert response.status_code == 200, response.text
    return response.json()


def _restart():
    scan_routes._scan_store.clear()


def test_a_scan_reopens_after_a_restart(client):
    live = _scan(client)
    _restart()

    assert client.get(f"/api/scan/{live['scan_id']}/status").json() == {
        "scan_id": live["scan_id"], "held": True, "archived": True}
    restored = client.get(f"/api/scan/{live['scan_id']}").json()
    assert restored["archived"] is True
    assert restored["posture"] == live["posture"] and restored["coverage"] == live["coverage"]
    assert [(r["control_id"], r["status"]) for r in restored["results"]] == \
           [(r["control_id"], r["status"]) for r in live["results"]]


def test_an_archived_scan_still_gets_its_pdf_with_remediation(client):
    scan_id = _scan(client)["scan_id"]
    _restart()
    response = client.post("/api/report", json={"scan_id": scan_id})
    assert response.status_code == 200 and response.content.startswith(b"%PDF")


def test_an_archived_scan_shows_its_plan_but_cannot_be_acted_on(client):
    scan_id = _scan(client)["scan_id"]
    live_plan = client.post("/api/remediation/plan", json={"scan_id": scan_id}).json()
    _restart()
    plan = client.post("/api/remediation/plan", json={"scan_id": scan_id})
    assert plan.status_code == 200
    assert [r["rule_id"] for d in plan.json()["devices"] for r in d["remediations"]] == \
           [r["rule_id"] for d in live_plan["devices"] for r in d["remediations"]]
    response = client.get(f"/api/adaptive/scans/{scan_id}/provisional")
    assert response.status_code == 409 and "Upload the configuration again" in response.json()["detail"]


def test_the_archive_holds_no_secret(client):
    scan_id = _scan(client)["scan_id"]
    with get_connection() as conn:
        row = conn.execute("SELECT response, plans FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    stored = row["response"] + row["plans"]
    assert "ARCHIVE-01" in stored
    assert not any(secret in stored for secret in SECRETS)


def test_an_unknown_scan_is_still_not_found(client):
    assert client.get("/api/scan/no-such-scan").status_code == 404
    assert client.get("/api/scan/no-such-scan/status").json()["held"] is False
