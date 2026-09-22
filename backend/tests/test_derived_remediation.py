"""
Derived remediation: the change NetAuditAI works out for itself on an unconfirmed vendor.

    decisive FAIL → the lines it cites → removed from a copy → the copy re-read by the generic engine
    → the finding is gone and nothing else got worse → a candidate an administrator confirms

No vendor grammar, no AI, no new authority: the derivation only states which lines to remove, and the
existing candidate verification is what decides whether it holds. These tests hold it to that -it must
work across dialects it was never taught, refuse what it cannot state safely, never edit the upload, and
never turn a provisional reading into a fix.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.remediation import candidates as cand

SAMPLES = Path(__file__).resolve().parents[2] / "sample"
DIALECTS = Path(__file__).resolve().parent / "fixtures" / "seed_dialects"

# A hierarchical dialect no parser reads: Telnet is on, and a policy permits everything
JUNOS = """system {
    host-name EDGE-9;
    services {
        ssh {
            protocol-version v2;
        }
        telnet;
    }
    syslog {
        host 192.0.2.20 {
            any notice;
        }
    }
}
"""


@pytest.fixture
def client(seeded_adaptive_db):
    return TestClient(app)


def scan(client, name: str, text: str) -> tuple[str, dict]:
    response = client.post("/api/scan", files={"files": (name, io.BytesIO(text.encode()), "text/plain")})
    assert response.status_code == 200, response.text
    return response.json()["scan_id"], response.json()


def _host(client, scan_id: str, index: int = 0) -> str:
    return client.get(f"/api/scan/{scan_id}").json()["devices"][index]["hostname"]


def derive(client, scan_id: str, rule_id: str, index: int = 0):
    return client.post("/api/remediation/candidate/derive", json={
        "scan_id": scan_id, "rule_id": rule_id,
        "device_hostname": _host(client, scan_id, index), "config_index": index,
    })


# ── what it derives ──────────────────────────────────────────────────────────

def test_it_derives_and_verifies_a_fix_without_ai_or_vendor_grammar(client):
    scan_id, _ = scan(client, "edge.cfg", JUNOS)
    body = derive(client, scan_id, "MGMT-001").json()

    assert body["source"] == "derived"
    assert body["status"] == "verified"
    assert body["command"] == "delete system services telnet"
    assert body["control_status_before"] == "fail"
    assert body["control_status_after"] == "not_configured"
    assert "telnet;" in "".join(body["evidence"]["lines"])
    # verified by the same three checks any candidate faces
    assert {c["name"] for c in body["checks"]} == {"target", "no_regression", "generic_path"}
    assert all(c["passed"] for c in body["checks"])
    assert "-        telnet;" in body["diff"]
    assert body["download_available"] is True


def test_the_change_is_the_line_in_its_own_block_not_a_guessed_command(client):
    """The words come from the configuration: its block path, then the statement's own keywords."""
    scan_id, _ = scan(client, "juniper-test.cfg", (SAMPLES / "juniper-test.cfg").read_text(encoding="utf-8"))
    body = derive(client, scan_id, "MGMT-002").json()
    assert body["command"] == "delete system services web-management http"
    assert body["status"] == "verified"


@pytest.mark.parametrize("name", ["junos.conf", "panos.conf", "routeros.rsc", "huawei.conf"])
def test_it_works_on_dialects_nobody_taught_this_deployment(client, name):
    scan_id, _ = scan(client, name, (DIALECTS / name).read_text(encoding="utf-8"))
    body = derive(client, scan_id, "MGMT-001").json()
    assert body["status"] == "verified", body["reason"]
    assert body["control_status_after"] != "fail"
    # the derived text quotes the file's own words, never a vendor command table
    assert body["command"].startswith("delete ")


# ── what it refuses ──────────────────────────────────────────────────────────

def test_a_setting_that_must_exist_is_never_deleted_to_make_a_check_stop_failing(client):
    """An idle timeout of 30 minutes is too long -but deleting it leaves no timeout at all.

    A removal can only honestly resolve a control that says something must NOT be there. NetAuditAI
    refuses to derive one for a control that requires a setting or holds it to a threshold, even though
    removing the line would make the control stop reporting FAIL.
    """
    text = (DIALECTS / "panos.conf").read_text(encoding="utf-8")
    scan_id, body = scan(client, "panos.conf", text)
    assert any(r["control_id"] == "MGMT-006" and r["status"] == "fail" and r["assurance"] == "confirmed"
               for r in body["results"])

    assert cand.derive(text, 0, "MGMT-006") is None
    response = derive(client, scan_id, "MGMT-006")
    assert response.status_code == 422
    assert "needs a setting to be added" in response.json()["detail"]


def test_a_control_that_needs_a_setting_added_has_nothing_to_remove(client):
    """LOG-001 without a syslog server never decisively fails, so there is no candidate to derive at all."""
    scan_id, _ = scan(client, "edge.cfg", JUNOS.replace("""    syslog {
        host 192.0.2.20 {
            any notice;
        }
    }
""", ""))
    response = derive(client, scan_id, "LOG-001")
    assert response.status_code == 409
    assert "needs a confirmed failure" in response.json()["detail"]


def test_a_block_opener_is_never_removed_on_its_own():
    """Removing ``lldp {`` alone would orphan its contents: the change is not stated at all."""
    text = "protocols {\n    lldp {\n        interface all;\n    }\n}\n"
    lines = text.splitlines()
    assert 2 in cand.block_openers(lines)
    assert cand.derived_command(text, [2]) is None
    # the leaf inside it can be stated
    assert cand.derived_command(text, [3]) == "delete protocols lldp interface all"


def test_a_provisional_finding_cannot_be_derived_from(client):
    """Only decisive failures have evidence to remove; a heuristic reading is not one."""
    text = "snmp {\n    community public {\n        authorization read-write;\n    }\n}\n"
    scan_id, body = scan(client, "snmp.cfg", text)
    provisional = [r for r in body["results"] if r["control_id"] == "MGMT-004"]
    assert provisional and all(r["assurance"] in (None, "heuristic") for r in provisional)
    response = derive(client, scan_id, "MGMT-004")
    assert response.status_code == 409
    assert "needs a confirmed failure" in response.json()["detail"]


def test_a_confirmed_vendor_keeps_its_own_deterministic_path(client):
    """Cisco has recipes; candidates are for configurations with no confirmed grammar."""
    scan_id, _ = scan(client, "cisco.cfg", "hostname R1\n!\nline vty 0 4\n transport input telnet ssh\n!\n")
    assert derive(client, scan_id, "MGMT-001").status_code == 409


# ── what it never does ───────────────────────────────────────────────────────

def test_the_uploaded_configuration_is_never_edited(client):
    scan_id, _ = scan(client, "edge.cfg", JUNOS)
    before = client.get(f"/api/adaptive/scans/{scan_id}/configs/0/lines").json()
    assert derive(client, scan_id, "MGMT-001").json()["status"] == "verified"
    after = client.get(f"/api/adaptive/scans/{scan_id}/configs/0/lines").json()
    assert before == after


def test_deriving_changes_nothing_about_the_scan(client):
    scan_id, before = scan(client, "edge.cfg", JUNOS)
    derive(client, scan_id, "MGMT-001")
    after = client.get(f"/api/scan/{scan_id}").json()
    assert (after["posture"], after["coverage"]) == (before["posture"], before["coverage"])
    assert after["assessed_count"] == before["assessed_count"]
    assert [r["status"] for r in after["results"]] == [r["status"] for r in before["results"]]


def test_a_derived_candidate_still_needs_a_human_and_is_never_applied(client):
    scan_id, _ = scan(client, "edge.cfg", JUNOS)
    body = derive(client, scan_id, "MGMT-001").json()
    assert body["confirmed_at"] is None
    assert "does not establish that the command is safe to run on the physical device" in body["reason"]

    confirmed = client.post("/api/remediation/candidate/confirm", json={
        "scan_id": scan_id, "rule_id": "MGMT-001", "device_hostname": _host(client, scan_id), "config_index": 0,
    }).json()
    assert confirmed["status"] == "confirmed"
    assert "has not connected to the device" in confirmed["reason"]
    # confirming a candidate never moves the scan's own numbers
    after = client.get(f"/api/scan/{scan_id}").json()
    assert after["coverage"] == client.get(f"/api/scan/{scan_id}").json()["coverage"]
    assert [r["status"] for r in after["results"] if r["control_id"] == "MGMT-001"] == ["fail"]
