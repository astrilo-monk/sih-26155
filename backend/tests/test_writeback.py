"""Seed write-back: a reviewed recognizer that read a failing line writes its secure form, verified by a rescan."""

from __future__ import annotations

import ipaddress
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.remediation.engine import RemediationStatus, analyze_generic_text
from app.remediation.writeback import writeback_all, writeback_control

PANOS = """set deviceconfig system hostname PA-WB-01
set deviceconfig system service disable-telnet no
set deviceconfig system service disable-http no
set deviceconfig system ssh service protocol-version v1
set deviceconfig setting management idle-timeout 0
set network profiles interface-management-profile UNTRUST telnet yes
set network profiles interface-management-profile UNTRUST permitted-ip 0.0.0.0/0
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 192.0.2.10
set deviceconfig system ntp-servers primary-ntp-server authentication-type none
set rulebase security rules ALLOW-ALL source any
set rulebase security rules ALLOW-ALL destination any
set rulebase security rules ALLOW-ALL action allow
"""
SUBNET = {"management_subnet": ipaddress.IPv4Network("10.50.0.0/24")}


def _status(plan, control_id):
    return next(o.status for o in plan.outcomes if o.control_id == control_id)


def test_each_failing_line_is_rewritten_by_the_recognizer_that_read_it(seeded_adaptive_db):
    plan = writeback_all(PANOS, SUBNET)
    assert set(plan.fixed_controls) == {"MGMT-001", "MGMT-002", "MGMT-003", "MGMT-006", "MGMT-007"}
    fixed = plan.fixed_config.splitlines()
    assert "set deviceconfig system service disable-telnet yes" in fixed
    assert "set deviceconfig system service disable-http yes" in fixed
    assert "set deviceconfig system ssh service protocol-version v2" in fixed
    assert "set deviceconfig setting management idle-timeout 10" in fixed
    assert "set network profiles interface-management-profile UNTRUST telnet no" in fixed
    assert "set network profiles interface-management-profile UNTRUST permitted-ip 10.50.0.0/24" in fixed
    # every other line is untouched, in place
    assert len(fixed) == len(PANOS.splitlines())
    assert plan.after["posture"] > plan.before["posture"]


def test_the_corrected_copy_rescans_as_confirmed_passes(seeded_adaptive_db):
    after = analyze_generic_text(writeback_all(PANOS, SUBNET).fixed_config)
    for control_id in ("MGMT-001", "MGMT-002", "MGMT-003", "MGMT-006", "MGMT-007"):
        assert {(r.status.value, r.assurance.value) for r in after.control(control_id)} == {("pass", "confirmed")}


def test_a_value_only_the_operator_knows_is_asked_for(seeded_adaptive_db):
    outcome, after = writeback_control(PANOS, "MGMT-003", {})
    assert outcome.status == RemediationStatus.NEEDS_INPUT and outcome.missing_inputs == ["management_subnet"]
    assert after is None


def test_what_no_recognizer_can_write_is_left_to_the_candidate_path(seeded_adaptive_db):
    plan = writeback_all(PANOS, SUBNET)
    # NTP authentication also needs a key the recognizer does not describe
    assert _status(plan, "LOG-002") == RemediationStatus.NO_RECIPE
    # the any-any rule is only a heuristic reading: never remediated
    assert _status(plan, "BOUNDARY-001") == RemediationStatus.PROVISIONAL
    assert "authentication-type none" in plan.fixed_config
    assert "set rulebase security rules ALLOW-ALL action allow" in plan.fixed_config


@pytest.mark.parametrize("text, control_id, expected", [
    ("set telnet-server enabled true\n", "MGMT-001", "set telnet-server enabled false"),              # Gaia
    ("set system services ssh protocol-version v1\n", "MGMT-007", "set system services ssh protocol-version v2"),
    ("system {\n  login {\n    class OPS {\n      idle-timeout 60;\n    }\n  }\n}\n", "MGMT-006",
     "      idle-timeout 10;"),                                                                        # keeps indentation
])
def test_other_dialects_keep_their_own_syntax(seeded_adaptive_db, text, control_id, expected):
    outcome, _ = writeback_control(text, control_id, {})
    assert outcome.status == RemediationStatus.FIXED, outcome.reason
    assert expected in outcome.fixed_config.splitlines()


def test_a_toggle_whose_negation_differs_per_dialect_is_not_written(seeded_adaptive_db):
    # ``{neg} feature telnet``: ``no`` on NX-OS, but the recognizer does not say which negator a dialect uses
    outcome, _ = writeback_control("feature telnet\n", "MGMT-001", {})
    assert outcome.status == RemediationStatus.NO_RECIPE


def _scan(client: TestClient, text: str) -> dict:
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        response = client.post("/api/scan", files=[("files", ("pa.cfg", text.encode(), "text/plain"))])
    assert response.status_code == 200, response.text
    return response.json()


def test_api_plan_and_download_treat_written_back_fixes_like_a_parsed_vendors(seeded_adaptive_db):
    client = TestClient(app)
    scan = _scan(client, PANOS)
    assert scan["vendor_identification"][0]["status"] != "confirmed"

    plan = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    statuses = {r["rule_id"]: r["status"] for r in plan["remediations"]}
    assert statuses["MGMT-001"] == statuses["MGMT-007"] == "fixed"
    assert statuses["MGMT-003"] == "needs_input"
    assert statuses["LOG-002"] == "vendor_unverified"          # the candidate path, as before
    assert plan["fixed_config"] and "MGMT-001" in plan["fixed_controls"]

    download = client.post("/api/download-fixed", json={"scan_id": scan["scan_id"],
                                                        "inputs": {"management_subnet": "10.50.0.0/24"}})
    assert download.status_code == 200
    assert "disable-telnet yes" in download.text and "permitted-ip 10.50.0.0/24" in download.text

    one = client.post("/api/remediate", json={"scan_id": scan["scan_id"], "rule_id": "MGMT-002",
                                              "device_hostname": plan["device_hostname"], "config_index": 0})
    assert one.json()["status"] == "fixed"


# ── a command someone else wrote (the administrator, or the AI) ─────────────

@pytest.mark.parametrize("command, fixed", [
    # the dialect's own syntax, read by reviewed recognizers: applied and verified
    ("set deviceconfig system service disable-telnet yes\n"
     "set network profiles interface-management-profile UNTRUST telnet no", True),
    # plausible, but not this dialect: no recognizer reads it
    ("set system services telnet disable", False),
    # right syntax, plus a line the engine cannot read: nothing of it is applied
    ("set deviceconfig system service disable-telnet yes\nset deviceconfig system telnet-banner off", False),
    # read, but it leaves Telnet on
    ("set deviceconfig system service disable-telnet no", False),
])
def test_a_command_joins_the_corrected_copy_only_when_recognizers_read_it_and_it_passes(
        seeded_adaptive_db, command, fixed):
    outcome, after = writeback_control(PANOS, "MGMT-001", {}, command=command)
    assert (outcome.status == RemediationStatus.FIXED) is fixed, outcome.reason
    assert (after is not None) is fixed


def test_a_negation_is_never_written_into_the_file_as_a_line(seeded_adaptive_db):
    from app.remediation.writeback import applied_command
    assert applied_command("feature telnet\n", "no feature telnet", "MGMT-001") is None


def test_api_a_confirmed_command_the_recognizers_read_is_part_of_the_corrected_configuration(seeded_adaptive_db):
    client = TestClient(app)
    scan = _scan(client, PANOS)
    body = {"scan_id": scan["scan_id"], "rule_id": "LOG-002", "device_hostname": "PA-WB-01", "config_index": 0}
    command = "set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key"

    proposed = client.post("/api/remediation/candidate", json={**body, "command": command}).json()
    verified = client.post("/api/remediation/candidate/verify", json=body).json()
    assert (verified["status"], verified["effect"]) == ("verified", "applied"), verified["reason"]
    assert verified["control_status_after"] == "pass"

    # before it is confirmed, the corrected configuration does not include it
    plan = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    assert "LOG-002" not in plan["fixed_controls"]

    client.post("/api/remediation/candidate/confirm", json=body)
    plan = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    assert "LOG-002" in plan["fixed_controls"] and proposed["source"] == "manual"
    download = client.post("/api/download-fixed", json={"scan_id": scan["scan_id"]})
    assert "authentication-type symmetric-key" in download.text


def test_api_a_removal_verified_candidate_stays_out_of_the_corrected_configuration(seeded_adaptive_db):
    """Removing the line proves the finding is gone, not that the setting is secure."""
    client = TestClient(app)
    scan = _scan(client, PANOS)
    body = {"scan_id": scan["scan_id"], "rule_id": "LOG-002", "device_hostname": "PA-WB-01", "config_index": 0}
    client.post("/api/remediation/candidate", json={**body, "command":
                "delete deviceconfig system ntp-servers primary-ntp-server authentication-type none"})
    verified = client.post("/api/remediation/candidate/verify", json=body).json()
    client.post("/api/remediation/candidate/confirm", json=body)
    plan = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    assert verified["effect"] != "applied"
    assert "LOG-002" not in plan["fixed_controls"]
