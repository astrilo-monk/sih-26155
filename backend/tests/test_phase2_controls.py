"""
Phase 2 -control catalog and ControlResults.

Every control answers every config with PASS / FAIL / NOT_CONFIGURED /
UNKNOWN / N_A. Findings are the FAIL results, framework mappings live in the
catalog with their version, and no control reports PASS without evidence.
"""

import json
from collections import defaultdict
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import app.remediation.engine as remediation_engine
from app.adaptive.capture import capture_unrecognized_lines
from app.analysis.engine import analyze, evaluate_controls
from app.controls.catalog import CIS, CONTROLS, NIST, ControlKind
from app.controls.judges import JUDGES
from app.controls.views import finding_from_result
from app.main import app
from app.facts.predicates import PREDICATES
from app.models.normalized import AIFieldMapping, DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Status
from app.parsers.detector import identify_vendor

TESTS = Path(__file__).parent
REPO = TESTS.parent.parent
SNAPSHOT = json.loads((TESTS / "snapshots" / "phase0_findings.json").read_text())

ORIGINAL_RULE_IDS = {
    "MGMT-001", "MGMT-002", "MGMT-003", "MGMT-004", "MGMT-005", "MGMT-006", "MGMT-007", "MGMT-008",
    "MGMT-009", "BOUNDARY-001", "BOUNDARY-002", "BOUNDARY-003", "LOG-001", "LOG-002", "CRYPTO-001",
}
# Controls added after the original catalog: new questions, held to the same description rules
ADDED_RULE_IDS = {
    "MGMT-010", "MGMT-011", "AUTH-001", "AUTH-002", "AUTH-003", "LOG-003", "CRYPTO-002", "BOUNDARY-004",
    "MGMT-012", "BOUNDARY-005", "BOUNDARY-006", "CRYPTO-003",
}
RULE_IDS = ORIGINAL_RULE_IDS | ADDED_RULE_IDS

# NIST SP 800-53 Rev. 5 ids and titles as published in the official OSCAL
# catalog, release 5.2.0 (usnistgov/oscal-content).
NIST_REV5_TITLES = {
    "AC-2": "Account Management",
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-7": "Unsuccessful Logon Attempts",
    "AU-2": "Event Logging",
    "AU-12": "Audit Record Generation",
    "AC-8": "System Use Notification",
    "AC-11": "Device Lock",
    "AC-12": "Session Termination",
    "AC-17(1)": "Monitoring and Control",
    "AC-17(2)": "Protection of Confidentiality and Integrity Using Encryption",
    "AU-4(1)": "Transfer to Alternate Storage",
    "AU-8": "Time Stamps",
    "AU-9(2)": "Store on Separate Physical Systems or Components",
    "CM-7": "Least Functionality",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-3": "Device Identification and Authentication",
    "IA-5": "Authenticator Management",
    "IA-5(1)": "Password-based Authentication",
    "SC-7": "Boundary Protection",
    "SC-7(5)": "Deny by Default -Allow by Exception",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-10": "Network Disconnect",
    "SC-13": "Cryptographic Protection",
    "SC-45": "System Time Synchronization",
    "SC-45(1)": "Synchronization with Authoritative Time Source",
}
NIST_REV5_WITHDRAWN = {"AU-8(1)", "AU-8(2)"}


# ── catalog ──────────────────────────────────────────────────────────────────

def test_catalog_has_exactly_one_control_per_rule():
    assert set(CONTROLS) == RULE_IDS
    assert set(JUDGES) == RULE_IDS


@pytest.mark.parametrize("control_id", sorted(RULE_IDS))
def test_every_control_is_fully_described(control_id):
    control = CONTROLS[control_id]
    # Phase 8: remediation keys name the deterministic recipes (control, vendor)
    templates = {control_id for control_id, _ in remediation_engine.RECIPES}

    assert control.title and control.question.endswith("?")
    assert isinstance(control.kind, ControlKind)
    assert control.category in {"management", "authentication", "boundary", "logging", "cryptography"}
    assert any(m.framework == NIST for m in control.mappings)
    assert all(m.version for m in control.mappings)
    assert control.remediation_keys and all(key in templates for key in control.remediation_keys)
    assert control.needs and set(control.needs) <= PREDICATES


def test_nist_mappings_are_current_rev5_controls_with_official_titles():
    for control in CONTROLS.values():
        for mapping in (m for m in control.mappings if m.framework == NIST):
            assert mapping.requirement_id not in NIST_REV5_WITHDRAWN, control.control_id
            assert NIST_REV5_TITLES.get(mapping.requirement_id) == mapping.title, (control.control_id, mapping)


def test_withdrawn_au_8_1_was_replaced_by_sc_45_1():
    ids = {m.requirement_id for m in CONTROLS["LOG-002"].mappings}
    assert "SC-45(1)" in ids and "AU-8(1)" not in ids


def test_cis_mappings_are_product_specific_and_versioned():
    for control in CONTROLS.values():
        for mapping in (m for m in control.mappings if m.framework == CIS):
            assert mapping.vendor in (Vendor.CISCO_IOS, Vendor.FORTINET), control.control_id
            assert "Benchmark v" in mapping.version and "Level" in mapping.version


# ── results over every kind of config ───────────────────────────────────────

def _unknown_config(text: str) -> NormalizedConfig:
    cfg = NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="unknown"),
                           raw_config=text, raw_lines=text.splitlines())
    capture_unrecognized_lines(cfg)
    return cfg


def _config_for(path: Path) -> NormalizedConfig:
    text = path.read_text(encoding="utf-8")
    identification = identify_vendor(text)
    if identification.confirmed:
        capture_unrecognized_lines(identification.config)
        return identification.config
    return _unknown_config(text)


ALL_CONFIG_FILES = (
    [REPO / e["file"] for e in SNAPSHOT["entries"]]
    + sorted((TESTS / "fixtures" / "lookalikes").glob("*.cfg"))
    + [REPO / "sample" / "unknown.cfg", REPO / "sample" / "paloalto.cfg"]
)


@pytest.mark.parametrize("path", ALL_CONFIG_FILES, ids=lambda p: p.name)
def test_every_control_answers_every_config(path):
    results = evaluate_controls(_config_for(path))
    by_control = defaultdict(list)
    for result in results:
        by_control[result.control_id].append(result)

    assert set(by_control) == RULE_IDS
    for control_id, answers in by_control.items():
        if any(r.status == Status.FAIL for r in answers):
            # one FAIL per failing scope, never mixed with other statuses
            assert all(r.status == Status.FAIL and r.failure is not None for r in answers), control_id
        else:
            assert len(answers) == 1, control_id
            assert answers[0].failure is None and answers[0].reason, control_id


@pytest.mark.parametrize("path", ALL_CONFIG_FILES, ids=lambda p: p.name)
def test_no_decision_without_evidence_or_assurance(path):
    config = _config_for(path)
    for result in evaluate_controls(config):
        if result.status == Status.PASS:
            # a documented vendor default decides without a configuration line (Phase 4)
            assert result.assurance is not None and (result.evidence or result.assurance == Assurance.DEFAULT), result
        if result.decided and config.device.vendor != Vendor.UNKNOWN:
            assert result.assurance in (Assurance.PARSER, Assurance.DEFAULT), result
        if config.device.vendor == Vendor.UNKNOWN and result.decided:
            # no adaptive values applied here: only provisional lexicon heuristics decide (Phase 5)
            assert result.assurance == Assurance.HEURISTIC and result.evidence, result


@pytest.mark.parametrize("entry", SNAPSHOT["entries"], ids=lambda e: e["file"])
def test_findings_are_exactly_the_fail_results(entry):
    config = _config_for(REPO / entry["file"])
    result = analyze(config)
    fails = [r for r in result.results if r.status == Status.FAIL]

    assert [f.rule_id for f in result.findings] == [r.control_id for r in fails]
    # the snapshot holds the original controls' findings; added controls may only add findings of their own
    assert sorted([f.rule_id, f.severity.value, f.line_numbers] for f in result.findings
                  if f.rule_id in ORIGINAL_RULE_IDS) == entry["findings"]
    assert all(finding_from_result(r).severity.value in {"critical", "high", "medium", "low"} for r in fails)


def test_fail_severity_never_exceeds_the_catalog_severity():
    order = ["low", "medium", "high", "critical"]
    for entry in SNAPSHOT["entries"]:
        for result in evaluate_controls(_config_for(REPO / entry["file"])):
            if result.status == Status.FAIL:
                control = CONTROLS[result.control_id]
                assert order.index(result.failure.severity.value) <= order.index(control.severity.value)


def test_status_examples_on_known_vendor_fixtures():
    cisco = {r.control_id: r for r in evaluate_controls(_config_for(TESTS / "fixtures" / "cisco_secure.cfg"))}
    assert cisco["MGMT-008"].status == Status.PASS
    assert any("aaa new-model" in line for line in cisco["MGMT-008"].evidence.text)

    fortinet = {r.control_id: r for r in evaluate_controls(_config_for(TESTS / "fixtures" / "fortinet_secure.cfg"))}
    for cisco_only in ("MGMT-005", "MGMT-008"):
        assert fortinet[cisco_only].status == Status.UNKNOWN
        assert "fortinet" in fortinet[cisco_only].reason


# ── unknown vendors ──────────────────────────────────────────────────────────

def _applied(field: str, value: str, line: int, source: str = "learned_mapping") -> AIFieldMapping:
    return AIFieldMapping(
        line_number=line, raw_line="x", normalized_field=field, extracted_value=value,
        confidence=0.95, confidence_tier="high", reasoning="", source=source, final_value=value,
    )


def test_unknown_vendor_without_evidence_is_never_pass_or_fail():
    results = {r.control_id: r for r in evaluate_controls(_unknown_config("remote-console protocol telnet\n"))}
    assert not any(r.decided for r in results.values())
    assert results["MGMT-001"].status == Status.NOT_CONFIGURED       # prohibition, no fact
    assert results["MGMT-003"].status == Status.UNKNOWN              # relational, no fact
    assert results["LOG-001"].status == Status.NOT_CONFIGURED


@pytest.mark.parametrize("source,assurance,status,proposed", [
    ("learned_mapping", Assurance.CONFIRMED, Status.PASS, None),
    ("admin_confirmed", Assurance.CONFIRMED, Status.PASS, None),
    # an AI verdict is a proposal until a human confirms it (Phase 7)
    ("ai_auto_mapped", Assurance.AI_VERIFIED, Status.UNKNOWN, Status.PASS),
])
def test_unknown_vendor_decision_carries_the_assurance_of_its_evidence(source, assurance, status, proposed):
    cfg = _unknown_config("audit-stream destination 10.44.60.20\n")
    cfg.logging.remote_hosts.append("10.44.60.20")
    cfg.logging.source_lines.append(1)
    cfg.ai_mappings.append(_applied("logging.remote_hosts", "10.44.60.20", 1, source))

    log001 = next(r for r in evaluate_controls(cfg) if r.control_id == "LOG-001")
    assert (log001.status, log001.proposed_status) == (status, proposed)
    assert log001.assurance == assurance
    assert log001.evidence.line_numbers == [1]


def test_formerly_vendor_gated_control_evaluates_a_confirmed_mapping():
    # Phase 4 removed the vendor gates: a confirmed mapping is a decisive fact for every control
    cfg = _unknown_config("remote-console protocol telnet\n")
    cfg.management.telnet_enabled = True
    cfg.ai_mappings.append(_applied("management.telnet_enabled", "true", 1))

    mgmt001 = next(r for r in evaluate_controls(cfg) if r.control_id == "MGMT-001")
    assert mgmt001.status == Status.FAIL
    assert mgmt001.assurance == Assurance.CONFIRMED
    assert mgmt001.evidence.line_numbers == [1]


def test_ntp_server_without_known_authentication_is_unknown_not_pass():
    cfg = _unknown_config("time-sync server 10.44.70.10\n")
    cfg.ntp.servers.append("10.44.70.10")
    cfg.ntp.source_lines.append(1)
    cfg.ai_mappings.append(_applied("ntp.servers", "10.44.70.10", 1))

    log002 = next(r for r in evaluate_controls(cfg) if r.control_id == "LOG-002")
    assert log002.status == Status.UNKNOWN


def test_a_broken_control_yields_unknown_and_the_scan_continues():
    with patch.dict(JUDGES, {"MGMT-007": MagicMock(side_effect=RuntimeError("boom"))}):
        results = evaluate_controls(_config_for(TESTS / "fixtures" / "cisco_vulnerable.cfg"))
    broken = [r for r in results if r.control_id == "MGMT-007"]
    assert len(broken) == 1 and broken[0].status == Status.UNKNOWN and "boom" in broken[0].reason
    assert {r.control_id for r in results} == RULE_IDS


# ── API ──────────────────────────────────────────────────────────────────────

def _scan(fixture: str) -> dict:
    text = (TESTS / "fixtures" / fixture).read_bytes()
    resp = TestClient(app).post("/api/scan", files=[("files", (fixture, text, "text/plain"))])
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.parametrize("fixture", ["cisco_vulnerable.cfg", "fortinet_vulnerable.cfg", "cisco_secure.cfg"])
def test_api_returns_results_alongside_unchanged_findings(fixture):
    data = _scan(fixture)
    results = data["results"]

    assert {r["control_id"] for r in results} == RULE_IDS
    assert {r["status"] for r in results} <= {s.value for s in Status}
    assert sum(r["status"] == "fail" for r in results) == data["total_findings"]
    for r in results:
        assert r["config_index"] == 0 and r["question"] and r["title"] and r["reason"]
        if r["status"] == "pass" and r["assurance"] != "default":  # a documented vendor default cites no line
            assert r["evidence"]["line_numbers"] and r["evidence"]["lines"] and r["assurance"] == "parser"


def test_finding_compliance_comes_from_the_catalog_for_its_vendor():
    cisco = next(f for f in _scan("cisco_vulnerable.cfg")["findings"] if f["rule_id"] == "MGMT-001")
    fortinet = next(f for f in _scan("fortinet_vulnerable.cfg")["findings"] if f["rule_id"] == "MGMT-001")

    def ids(finding, framework):
        return {(c["control_id"], c["version"]) for c in finding["compliance"] if c["framework"] == framework}

    assert ("1.2.2", "Cisco IOS XE 17.x Benchmark v2.2.1 (Level 1)") in ids(cisco, "CIS")
    assert ("2.4.5", "FortiGate 7.4.x Benchmark v1.0.1 (Level 1)") in ids(fortinet, "CIS")
    assert not any("IOS" in version for _, version in ids(fortinet, "CIS"))
    assert ids(cisco, "NIST_800_53") == ids(fortinet, "NIST_800_53") != set()
    for framework in ("DISA_STIG", "ISO_27001"):  # vendor-neutral: identical for both vendors
        assert ids(cisco, framework) == ids(fortinet, framework) != set()
