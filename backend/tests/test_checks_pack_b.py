"""AUTH-001 (failed-login limit), AUTH-002 (password length) and AUTH-003 (default account names)."""

from __future__ import annotations

import pathlib

import pytest

from app.facts.heuristics import heuristic_facts
from app.facts.predicates import ADMIN_ACCOUNT
from app.models.results import Assurance, Status
from app.remediation.engine import RemediationStatus, analyze_generic_text, analyze_text, remediate_control
from app.remediation.writeback import writeback_control

REPO = pathlib.Path(__file__).parents[2]
# a full IOS configuration the detector confirms; it has 'username admin' and no lockout or length rule
IOS = (REPO / "demo-sih" / "cisco_edge_vulnerable.cfg").read_text(encoding="utf-8")
FORTI = (REPO / "sample" / "frontinet" / "04_fortigate_vulnerable.cfg").read_text(encoding="utf-8")


def _status(analysis, control_id):
    return {(r.status, r.assurance) for r in analysis.control(control_id)}


# ── Cisco IOS ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("line, expected", [
    ("", Status.FAIL),                                                      # IOS has no limit by default
    ("login block-for 900 attempts 3 within 120", Status.PASS),
    ("login block-for 60 attempts 20 within 60", Status.FAIL),              # more than 10
    ("aaa local authentication attempts max-fail 5", Status.PASS),
])
def test_ios_failed_login_limit(seeded_adaptive_db, line, expected):
    result = analyze_text(IOS.replace("ip domain name", f"{line}\nip domain name", 1))
    assert {r.status for r in result.control("AUTH-001")} == {expected}


@pytest.mark.parametrize("line, expected", [
    ("", Status.FAIL), ("security passwords min-length 6", Status.FAIL), ("security passwords min-length 12", Status.PASS),
])
def test_ios_password_length(seeded_adaptive_db, line, expected):
    result = analyze_text(IOS.replace("ip domain name", f"{line}\nip domain name", 1))
    assert {r.status for r in result.control("AUTH-002")} == {expected}


def test_ios_default_account_and_its_fixes(seeded_adaptive_db):
    assert {r.status for r in analyze_text(IOS).control("AUTH-003")} == {Status.FAIL}
    renamed = analyze_text(IOS.replace("username admin", "username noc-ops"))
    assert {r.status for r in renamed.control("AUTH-003")} == {Status.PASS}
    for control_id, expected in (("AUTH-001", "login block-for 900 attempts 3 within 120"),
                                 ("AUTH-002", "security passwords min-length 12")):
        outcome, _ = remediate_control(IOS, control_id, {})
        assert outcome.status == RemediationStatus.FIXED, outcome.reason
        assert expected in outcome.fixed_config.splitlines()
    assert remediate_control(IOS, "AUTH-003", {})[0].status == RemediationStatus.MANUAL_REVIEW


# ── FortiGate ───────────────────────────────────────────────────────────────

def test_fortigate_defaults_and_settings(seeded_adaptive_db):
    result = analyze_text(FORTI)
    # admin-lockout-threshold defaults to 3; the shipped 'admin' account exists unless renamed
    assert _status(result, "AUTH-001") == {(Status.PASS, Assurance.DEFAULT)}
    assert {r.status for r in result.control("AUTH-002")} == {Status.FAIL}
    weak = analyze_text(FORTI.replace("config system global", "config system global\n    set admin-lockout-threshold 20", 1))
    assert {r.status for r in weak.control("AUTH-001")} == {Status.FAIL}


def test_fortigate_password_policy_fix(seeded_adaptive_db):
    outcome, _ = remediate_control(FORTI, "AUTH-002", {})
    assert outcome.status == RemediationStatus.FIXED, outcome.reason
    assert "config system password-policy" in outcome.fixed_config and "set minimum-length 12" in outcome.fixed_config


# ── other dialects ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("line, control_id, expected", [
    ("set system login retry-options tries-before-disconnect 3", "AUTH-001", Status.PASS),
    ("set system login retry-options tries-before-disconnect 99", "AUTH-001", Status.FAIL),
    ("set system login password minimum-length 6", "AUTH-002", Status.FAIL),
    ("set mgt-config password-complexity minimum-length 16", "AUTH-002", Status.PASS),
    ("set mgt-config users admin permissions role-based superuser yes", "AUTH-003", Status.FAIL),
    ("set system login user root class super-user", "AUTH-003", Status.FAIL),
    ("set system login user noc-ops class super-user", "AUTH-003", Status.NOT_CONFIGURED),
    ("ssh server max-auth-attempts 3", "AUTH-001", Status.PASS),
])
def test_seeds_read_each_dialect(seeded_adaptive_db, line, control_id, expected):
    result = analyze_generic_text(f"{line}\n")
    assert {r.status for r in result.control(control_id)} == {expected}
    if expected != Status.NOT_CONFIGURED:
        assert {r.assurance for r in result.control(control_id)} == {Assurance.CONFIRMED}


def test_the_default_account_heuristic_ignores_snmp_users_and_other_names(seeded_adaptive_db):
    def names(line):
        return [f.value for f in heuristic_facts([line]) if f.predicate == ADMIN_ACCOUNT]
    assert names("username admin privilege 15 secret 5 $1$x") == ["admin"]
    assert names("snmp-server user admin NETOPS v3 auth sha x") == []
    assert names("username noc-ops privilege 15") == []


def test_write_back_raises_a_weak_limit_in_the_dialects_own_syntax(seeded_adaptive_db):
    outcome, _ = writeback_control("set system login retry-options tries-before-disconnect 99\n", "AUTH-001", {})
    assert outcome.status == RemediationStatus.FIXED, outcome.reason
    assert "set system login retry-options tries-before-disconnect 3" in outcome.fixed_config.splitlines()
    outcome, _ = writeback_control("set system login password minimum-length 6\n", "AUTH-002", {})
    assert "set system login password minimum-length 12" in outcome.fixed_config.splitlines()


def test_a_password_policy_line_is_not_mistaken_for_a_password():
    from app.ai.redaction import redact_line
    assert redact_line("set system login password minimum-length 12") == "set system login password minimum-length 12"
    assert "Hunter2x" not in redact_line("set system login user bob authentication plain-text-password-value Hunter2x")
