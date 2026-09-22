"""
Phase 4 -security facts and the generic control evaluator.

Controls read security facts, never vendor structures: every control runs on
every config. Vendor parsers are one fact source (PARSER), adaptive mappings
another (CONFIRMED / AI_VERIFIED), documented vendor defaults a third (DEFAULT).
FAIL parity with the Phase 0 snapshots is covered by test_phase0_snapshots.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.controls.evaluate as evaluate_module
import app.controls.judges as judges_module
from app.analysis.scoring import calculate_posture
from app.controls.catalog import CONTROLS, ControlKind
from app.controls.evaluate import evaluate_control, evaluate_controls
from app.facts.from_normalized import facts_from_config
from app.facts.predicates import (
    CENTRAL_AAA, IDLE_TIMEOUT, IPSEC_PROPOSAL, LOG_REMOTE_DESTINATION, NOT_SET, PREDICATES, PROTOCOL_ENABLED,
    SOURCE_RESTRICTED, SecurityFact,
)
from app.main import app
from app.models.normalized import AIFieldMapping, DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Evidence, Status
from app.parsers.detector import identify_vendor

TESTS = Path(__file__).parent
BACKEND = TESTS.parent


def _config(vendor: Vendor, lines: int = 3) -> NormalizedConfig:
    raw = [f"line {n}" for n in range(1, lines + 1)]
    return NormalizedConfig(device=DeviceInfo(vendor=vendor), raw_lines=raw, raw_config="\n".join(raw))


def _fact(predicate, value, lines=(1,), assurance=Assurance.PARSER, **kw) -> SecurityFact:
    return SecurityFact(predicate, value, assurance, Evidence(list(lines), [f"line {n}" for n in lines]), **kw)


def _one(control_id, facts, vendor=Vendor.UNKNOWN):
    results = evaluate_control(CONTROLS[control_id], facts, _config(vendor))
    assert len(results) == 1, results
    return results[0]


# ── vocabulary ───────────────────────────────────────────────────────────────

def test_every_predicate_is_consumed_by_a_control_and_every_need_exists():
    needed = {p for control in CONTROLS.values() for p in control.needs}
    assert needed == PREDICATES


def test_vendor_gated_rules_are_gone_and_judges_never_ask_the_vendor():
    assert not (BACKEND / "app" / "analysis" / "rules").exists()
    for module in (judges_module, evaluate_module):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "device.vendor ==" not in source and "device.vendor !=" not in source


@pytest.mark.parametrize("fixture", ["cisco_vulnerable.cfg", "fortinet_vulnerable.cfg"])
def test_parser_facts_are_cited_parser_facts_from_the_vocabulary(fixture):
    config = identify_vendor((TESTS / "fixtures" / fixture).read_text(encoding="utf-8")).config
    facts = facts_from_config(config)
    assert facts
    for fact in facts:
        assert fact.predicate in PREDICATES
        assert fact.assurance == Assurance.PARSER
        assert all(config.raw_lines[n - 1] == t for n, t in zip(fact.evidence.line_numbers, fact.evidence.text))


# ── decision table, one control per kind ────────────────────────────────────

def test_prohibition_decision_table():
    telnet = dict(subject="telnet")
    assert CONTROLS["MGMT-001"].kind == ControlKind.PROHIBITION
    assert _one("MGMT-001", [_fact(PROTOCOL_ENABLED, True, **telnet)]).status == Status.FAIL
    assert _one("MGMT-001", [_fact(PROTOCOL_ENABLED, False, **telnet)]).status == Status.PASS
    assert _one("MGMT-001", [_fact(PROTOCOL_ENABLED, None, **telnet)]).status == Status.UNKNOWN
    assert _one("MGMT-001", []).status == Status.NOT_CONFIGURED                       # unknown vendor, no fact
    assert _one("MGMT-001", [], Vendor.CISCO_IOS).status == Status.NOT_CONFIGURED     # no documented default
    # a fact about another subject does not answer the question
    assert _one("MGMT-001", [_fact(PROTOCOL_ENABLED, True, subject="http")]).status == Status.NOT_CONFIGURED


def test_requirement_decision_table():
    assert CONTROLS["LOG-001"].kind == ControlKind.REQUIREMENT
    assert _one("LOG-001", [_fact(LOG_REMOTE_DESTINATION, NOT_SET)], Vendor.CISCO_IOS).status == Status.FAIL
    assert _one("LOG-001", [_fact(LOG_REMOTE_DESTINATION, ["10.0.0.5"])]).status == Status.PASS
    assert _one("LOG-001", []).status == Status.NOT_CONFIGURED
    assert _one("MGMT-008", [_fact(CENTRAL_AAA, False)]).status == Status.FAIL        # explicitly disabled


def test_threshold_decision_table():
    assert CONTROLS["MGMT-006"].kind == ControlKind.THRESHOLD
    assert _one("MGMT-006", [_fact(IDLE_TIMEOUT, 30, unit="min")]).status == Status.FAIL
    assert _one("MGMT-006", [_fact(IDLE_TIMEOUT, 0, unit="min")]).status == Status.FAIL
    assert _one("MGMT-006", [_fact(IDLE_TIMEOUT, 5, unit="min")]).status == Status.PASS
    assert _one("MGMT-006", [_fact(IDLE_TIMEOUT, 5, unit=None)]).status == Status.UNKNOWN  # unit not stated
    assert _one("MGMT-006", []).status == Status.NOT_CONFIGURED


def test_relational_decision_table():
    assert CONTROLS["MGMT-003"].kind == ControlKind.RELATIONAL
    assert _one("MGMT-003", [_fact(SOURCE_RESTRICTED, False, scope="line vty 0 4")]).status == Status.FAIL
    assert _one("MGMT-003", [_fact(SOURCE_RESTRICTED, True)]).status == Status.PASS
    assert _one("MGMT-003", []).status == Status.UNKNOWN
    assert _one("MGMT-003", [], Vendor.FORTINET).status == Status.UNKNOWN


def test_an_optional_feature_the_device_does_not_have_is_not_applicable():
    """A router with no VPN is not undecided on VPN cryptography -the question does not arise."""
    assert CONTROLS["CRYPTO-001"].optional_feature
    absent = _one("CRYPTO-001", [], Vendor.CISCO_IOS)
    assert absent.status == Status.N_A and "does not apply" in absent.reason
    # only a parser can prove the absence; an unconfirmed vendor stays undecided
    assert _one("CRYPTO-001", []).status == Status.NOT_CONFIGURED
    # and a device that does have one is judged as before
    weak = _fact(IPSEC_PROPOSAL, {"encryption": "3des", "hash": "sha256", "dh_group": 14}, scope="proposal vpn1")
    assert _one("CRYPTO-001", [weak], Vendor.CISCO_IOS).status == Status.FAIL


def test_one_fail_per_failing_scope():
    facts = [_fact(PROTOCOL_ENABLED, True, (1,), subject="telnet", scope="interface wan1"),
             _fact(PROTOCOL_ENABLED, False, (2,), subject="telnet", scope="interface lan"),
             _fact(PROTOCOL_ENABLED, True, (3,), subject="telnet", scope="interface dmz")]
    results = evaluate_control(CONTROLS["MGMT-001"], facts, _config(Vendor.FORTINET))
    assert [(r.status, r.scope, r.evidence.line_numbers) for r in results] == [
        (Status.FAIL, "interface wan1", [1]), (Status.FAIL, "interface dmz", [3]),
    ]


def test_pass_without_a_cited_line_degrades_to_unknown():
    result = _one("MGMT-001", [_fact(PROTOCOL_ENABLED, False, (), subject="telnet")])
    assert result.status == Status.UNKNOWN and result.assurance is None


def test_decision_carries_the_weakest_assurance_of_its_facts():
    fact = _fact(PROTOCOL_ENABLED, True, subject="telnet", assurance=Assurance.AI_VERIFIED)
    assert _one("MGMT-001", [fact]).assurance == Assurance.AI_VERIFIED


@pytest.mark.parametrize("vendor", [Vendor.UNKNOWN, Vendor.PALO_ALTO])
@pytest.mark.parametrize("control_id", sorted(CONTROLS))
def test_unknown_vendor_without_facts_is_never_pass_or_fail(vendor, control_id):
    results = evaluate_control(CONTROLS[control_id], [], _config(vendor))
    assert [r.status for r in results] in ([Status.NOT_CONFIGURED], [Status.UNKNOWN])


# ── parser coverage and vendor defaults ─────────────────────────────────────

def test_a_setting_the_confirmed_parser_does_not_read_is_unknown():
    result = _one("MGMT-008", [], Vendor.FORTINET)
    assert result.status == Status.UNKNOWN and "fortinet parser" in result.reason


def test_documented_vendor_default_decides_when_the_config_is_silent():
    result = _one("MGMT-006", [], Vendor.FORTINET)
    assert result.status == Status.PASS
    assert result.assurance == Assurance.DEFAULT
    assert not result.evidence and "admintimeout 5" in result.reason


def test_insecure_fortios_default_fails_with_default_assurance():
    text = (TESTS / "fixtures" / "fortinet_secure.cfg").read_text(encoding="utf-8")
    silent = "\n".join(line for line in text.splitlines() if "pre-login-banner" not in line)
    identification = identify_vendor(silent)
    assert identification.confirmed

    banner = [r for r in evaluate_controls(identification.config) if r.control_id == "MGMT-009"]
    assert [(r.status, r.assurance) for r in banner] == [(Status.FAIL, Assurance.DEFAULT)]
    assert "pre-login-banner" in banner[0].failure.recommendation


# ── unknown vendors: adaptive mappings become facts ─────────────────────────

def _applied(field, value, line, source="learned_mapping") -> AIFieldMapping:
    return AIFieldMapping(line_number=line, raw_line="x", normalized_field=field, extracted_value=value,
                          confidence=0.95, confidence_tier="high", reasoning="", source=source, final_value=value)


def test_mapped_telnet_on_an_unknown_vendor_is_evaluated():
    config = _config(Vendor.UNKNOWN)
    config.ai_mappings.append(_applied("management.telnet_enabled", "true", 2, "ai_auto_mapped"))

    mgmt001 = [r for r in evaluate_controls(config) if r.control_id == "MGMT-001"]
    # AI verdicts are proposals (Phase 7): UNKNOWN with the proposed status
    assert [(r.status, r.proposed_status, r.assurance, r.evidence.line_numbers) for r in mgmt001] == [
        (Status.UNKNOWN, Status.FAIL, Assurance.AI_VERIFIED, [2]),
    ]
    # AI verdicts are provisional: never scored
    assert calculate_posture([evaluate_controls(config)]).posture is None


def test_conflicting_mapped_values_are_unknown():
    config = _config(Vendor.UNKNOWN)
    config.ai_mappings += [_applied("services.ip_source_route", "true", 1), _applied("services.ip_source_route", "false", 2)]
    result = next(r for r in evaluate_controls(config) if r.control_id == "BOUNDARY-002")
    assert result.status == Status.UNKNOWN and "Conflicting" in result.reason
    assert result.evidence.line_numbers == [1, 2]


def test_mapped_list_values_collect_into_one_fact():
    config = _config(Vendor.UNKNOWN)
    config.ai_mappings += [_applied("ntp.servers", "10.0.0.1", 1), _applied("ntp.servers", "10.0.0.2", 2),
                           _applied("ntp.authentication_enabled", "false", 3)]
    log002 = [r for r in evaluate_controls(config) if r.control_id == "LOG-002"]
    assert [(r.status, r.evidence.line_numbers) for r in log002] == [(Status.FAIL, [1, 2, 3])]


def test_scan_api_still_answers_every_control_for_an_unknown_config():
    path = BACKEND.parent / "sample" / "unknown.cfg"
    resp = TestClient(app).post("/api/scan", files=[("files", (path.name, path.read_bytes(), "text/plain"))])
    assert resp.status_code == 200, resp.text
    assert {r["control_id"] for r in resp.json()["results"]} == set(CONTROLS)
