"""CRYPTO-002 (weak management cryptography) and LOG-003 (traffic rules that do not log)."""

from __future__ import annotations

import pathlib

import pytest

from app.facts.heuristics import heuristic_facts
from app.facts.lexicon import is_weak_algorithm
from app.facts.predicates import MGMT_WEAK_CRYPTO, RULE_LOGGING
from app.models.results import Assurance, Status
from app.remediation.engine import RemediationStatus, analyze_text, remediate_control

REPO = pathlib.Path(__file__).parents[2]
IOS = (REPO / "demo-sih" / "cisco_edge_vulnerable.cfg").read_text(encoding="utf-8")
FORTI = (REPO / "sample" / "frontinet" / "04_fortigate_vulnerable.cfg").read_text(encoding="utf-8")


@pytest.mark.parametrize("name, weak", [
    ("3des-cbc", True), ("aes128-cbc", True), ("arcfour256", True), ("hmac-md5-96", True),
    ("diffie-hellman-group1-sha1", True), ("rsa-3des-ede-cbc-sha", True),
    ("aes256-ctr", False), ("aes256-gcm@openssh.com", False), ("chacha20-poly1305@openssh.com", False),
    ("hmac-sha2-256", False), ("diffie-hellman-group14-sha256", False), ("ecdhe-rsa-aes-128-gcm-sha256", False),
])
def test_weak_algorithm_names(name, weak):
    assert is_weak_algorithm(name) is weak


# ── CRYPTO-002 ──────────────────────────────────────────────────────────────

def test_ios_weak_ssh_algorithm_lists_fail_and_are_replaced(seeded_adaptive_db):
    text = IOS.replace("ip ssh version 1", "ip ssh version 1\nip ssh server algorithm encryption aes128-ctr 3des-cbc", 1)
    assert {r.status for r in analyze_text(text).control("CRYPTO-002")} == {Status.FAIL}
    outcome, _ = remediate_control(text, "CRYPTO-002", {})
    assert outcome.status == RemediationStatus.FIXED, outcome.reason
    assert "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr" in outcome.fixed_config.splitlines()
    # no algorithm list at all: the IOS release default decides, which is not claimed either way
    assert {r.status for r in analyze_text(IOS).control("CRYPTO-002")} == {Status.NOT_CONFIGURED}


@pytest.mark.parametrize("setting, expected", [
    ("", (Status.PASS, Assurance.DEFAULT)),                       # strong-crypto is on by default
    ("set strong-crypto disable", (Status.FAIL, Assurance.PARSER)),
    ("set ssh-hmac-md5 enable", (Status.FAIL, Assurance.PARSER)),
])
def test_fortigate_management_crypto(seeded_adaptive_db, setting, expected):
    text = FORTI.replace("config system global", f"config system global\n    {setting}", 1)
    assert {(r.status, r.assurance) for r in analyze_text(text).control("CRYPTO-002")} == {expected}


def test_fortigate_crypto_fix(seeded_adaptive_db):
    text = FORTI.replace("config system global", "config system global\n    set strong-crypto disable", 1)
    outcome, _ = remediate_control(text, "CRYPTO-002", {})
    assert outcome.status == RemediationStatus.FIXED, outcome.reason
    assert "set strong-crypto enable" in outcome.fixed_config


@pytest.mark.parametrize("line, weak", [
    ("ssh server cipher aes256_ctr aes128_ctr 3des_cbc", True),
    ("set system services ssh ciphers [ aes256-ctr aes128-ctr ]", False),
    ("set system login password format sha512", None),              # a password hash format, not SSH
])
def test_ssh_algorithm_lists_in_any_dialect(line, weak):
    values = [f.value for f in heuristic_facts([line]) if f.predicate == MGMT_WEAK_CRYPTO]
    assert values == ([weak] if weak is not None else [])


# ── LOG-003 ─────────────────────────────────────────────────────────────────

def test_fortigate_policy_logging(seeded_adaptive_db):
    assert {r.status for r in analyze_text(FORTI).control("LOG-003")} == {Status.PASS}
    off = FORTI.replace("set logtraffic all", "set logtraffic disable", 1)
    results = analyze_text(off).control("LOG-003")
    assert {r.status for r in results} == {Status.FAIL} and results[0].scope.startswith("firewall policy")
    outcome, _ = remediate_control(off, "LOG-003", {})
    assert outcome.status == RemediationStatus.FIXED, outcome.reason


def test_a_router_has_no_firewall_policies(seeded_adaptive_db):
    assert {r.status for r in analyze_text(IOS).control("LOG-003")} == {Status.N_A}


R = "set rulebase security rules R1 "
J = "set security policies from-zone trust to-zone untrust policy P "


@pytest.mark.parametrize("lines, expected", [
    ([R + "source any", R + "action allow", R + "log-end no"], False),
    ([R + "source any", R + "action allow", R + "log-end yes"], True),
    ([R + "source any", R + "action deny", R + "log-end no"], None),   # a deny rule
    ([J + "match source-address any", J + "then permit", J + "then log session-close"], True),
    ([J + "match source-address any", J + "then permit"], None),       # says nothing: the platform default
])
def test_rule_logging_in_set_style_rules(lines, expected):
    values = [f.value for f in heuristic_facts(lines) if f.predicate == RULE_LOGGING]
    assert values == ([expected] if expected is not None else [])


@pytest.mark.parametrize("text, control_id, expected", [
    ("/ip ssh set strong-crypto=yes forwarding-enabled=no\n", "CRYPTO-002", Status.PASS),
    ("/ip ssh set strong-crypto=no\n", "CRYPTO-002", Status.FAIL),
    ("set rulebase security rules ALLOW-WEB log-end no\n", "LOG-003", Status.FAIL),
])
def test_seeds_read_crypto_and_logging(seeded_adaptive_db, text, control_id, expected):
    from app.remediation.engine import analyze_generic_text
    result = analyze_generic_text(text)
    assert {(r.status, r.assurance) for r in result.control(control_id)} == {(expected, Assurance.CONFIRMED)}
