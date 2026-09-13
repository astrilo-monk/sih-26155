"""
Phase 5 — generic tokenizer + lexicon heuristics: unknown vendors get cited,
provisional results with no AI.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.analysis.scoring import calculate_posture
from app.controls.evaluate import evaluate_controls
from app.facts.heuristics import heuristic_facts
from app.facts.predicates import (
    IPSEC_PROPOSAL, LOG_REMOTE_DESTINATION, LOGIN_BANNER, NTP_SERVER, PERMIT_ANY, PROTOCOL_ENABLED,
)
from app.main import app
from app.models.normalized import AIFieldMapping, DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Status
from app.structure.tokenizer import tokenize, tokenize_line

REPO = Path(__file__).resolve().parents[2]


def _statement(lines: list[str], line: int):
    return next(s for s in tokenize(lines) if s.line == line)


# ── tokenizer: dialect shapes ───────────────────────────────────────────────

def test_indentation_scope():
    s = _statement(["line vty 0 4", " transport input telnet"], 2)
    assert s.scope_path == ("line vty 0 4",) and s.key_tokens == ["transport", "input", "telnet"]


def test_brace_scope():
    s = _statement(["system {", "  services {", "    telnet;", "  }", "}"], 3)
    assert s.scope_path == ("system", "services") and s.key_tokens == ["telnet"]


def test_config_edit_next_end_scope():
    lines = ["config system interface", '    edit "port1"', "        set allowaccess ping telnet", "    next", "end"]
    s = _statement(lines, 3)
    assert s.scope_path == ("config system interface", 'edit "port1"')
    assert s.key_tokens == ["allowaccess", "ping", "telnet"]


def test_flat_prefix_block_scope():
    statements = tokenize(["hostname gw", "remote-console state enabled", "remote-console protocol telnet"])
    assert [s.scope_path for s in statements] == [(), ("remote-console",), ("remote-console",)]


def test_set_path_with_self_negating_keyword():
    s = tokenize_line("set deviceconfig system service disable-telnet no")
    assert s.key_tokens == ["deviceconfig", "system", "service", "telnet"] and s.polarity is True


def test_slash_section_and_key_value():
    s = _statement(["/ip service", "set telnet disabled=yes address=10.0.0.0/8"], 2)
    assert s.scope_path == ("/ip service",) and s.key_tokens == ["telnet", "address"]
    assert s.values == ["10.0.0.0/8"] and s.polarity is False


@pytest.mark.parametrize("line,polarity", [
    ("no ip http server", False),
    ("telnet disabled", False),
    ("set telnet disabled=yes", False),
    ("set telnet disabled=no", True),
    ("telnet enabled=no", False),
    ("delete system services telnet", False),
    ("telnet-server state on", True),
    ("remote-console protocol telnet", None),
])
def test_negation(line, polarity):
    assert tokenize_line(line).polarity is polarity


def test_free_text_never_yields_facts():
    facts = heuristic_facts([
        "interface uplink0",
        ' description "telnet enabled for everyone"',
        "remark allow telnet any any",
        "banner motd ^C",
        "remote-console telnet enabled",
        "permit ip any any",
        "^C",
    ])
    assert [f.predicate for f in facts] == [LOGIN_BANNER]


def test_traffic_rules_and_account_toggles_are_not_management_facts():
    rule = ("set rulebase security rules Allow-Telnet from untrust to trust source any destination any "
            "application telnet service application-default action allow")
    assert not [f for f in heuristic_facts([rule]) if f.predicate in (PROTOCOL_ENABLED, PERMIT_ANY)]
    assert heuristic_facts(["no aaa root"]) == []  # Arista root account, not AAA


def test_block_state_never_crosses_a_blank_line():
    # a disabled state in another block must not turn Telnet into a probable PASS
    facts = heuristic_facts(["remote-console state disabled", "remote-console banner-text x", "",
                             "remote-console protocol telnet", "remote-console port 23"])
    assert not [f for f in facts if f.predicate == PROTOCOL_ENABLED]


def test_servers_in_a_disabled_block_are_not_destinations():
    facts = heuristic_facts(["syslog state disabled", "syslog server 10.1.1.1",
                             "time-sync state disabled", "time-sync server 10.2.2.2"])
    assert not [f for f in facts if f.predicate in (LOG_REMOTE_DESTINATION, NTP_SERVER)]


def test_separate_ipsec_blocks_are_separate_proposals():
    # merging them would hide the DES / MD5 proposal behind the first block's values
    facts = heuristic_facts(["secure-channel ipsec enabled", "secure-channel encryption aes256",
                             "secure-channel integrity sha256", "",
                             "secure-channel ipsec enabled", "secure-channel encryption des",
                             "secure-channel integrity md5", "secure-channel dhgrp 5"])
    proposals = sorted((f.value["encryption"], f.value["dh_group"]) for f in facts if f.predicate == IPSEC_PROPOSAL)
    assert proposals == [("aes256", None), ("des", 5)]


# ── acceptance: sample/unknown.cfg, offline ─────────────────────────────────

ACCEPTANCE = {
    "MGMT-001": (Status.FAIL, "heuristic", [70, 71]),          # suspected FAIL
    "MGMT-003": (Status.UNKNOWN, None, [67, 68, 72]),          # conflict
    "MGMT-007": (Status.PASS, "heuristic", [32]),              # probable PASS
    "LOG-001": (Status.PASS, "heuristic", [55]),               # telemetry line 88 not confused
    "MGMT-006": (Status.UNKNOWN, None, [38]),                  # unit not stated
    "LOG-002": (Status.PASS, "heuristic", [59, 60]),
    "MGMT-008": (Status.PASS, "heuristic", [48, 49, 50]),
    "CRYPTO-001": (Status.PASS, "heuristic", [76, 77, 78]),
    "MGMT-004": (Status.NOT_CONFIGURED, None, []),
    "MGMT-009": (Status.NOT_CONFIGURED, None, []),
}


def test_unknown_cfg_acceptance_table_with_zero_ai_calls():
    path = REPO / "sample" / "unknown.cfg"
    interpreter = MagicMock(side_effect=AssertionError("AI is unavailable"))
    with patch("app.api.routes.scan.interpret_lines", interpreter), \
         patch("app.api.routes.scan.is_available", return_value=False):
        resp = TestClient(app).post("/api/scan", files=[("files", (path.name, path.read_bytes(), "text/plain"))])
    assert resp.status_code == 200, resp.text
    data = resp.json()
    interpreter.assert_not_called()

    results = {r["control_id"]: r for r in data["results"]}
    actual = {cid: (Status(results[cid]["status"]), results[cid]["assurance"],
                    sorted(results[cid]["evidence"]["line_numbers"])) for cid in ACCEPTANCE}
    assert actual == ACCEPTANCE
    assert "Conflicting" in results["MGMT-003"]["reason"]
    assert "unit" in results["MGMT-006"]["reason"]

    # provisional: shown as a suspected finding, never scored
    assert [f["assurance"] for f in data["findings"]] == ["heuristic"]
    assert data["posture"] is None and data["coverage"] == 0 and data["score"] is None


# ── precedence and scoring ─────────────────────────────────────────────────

def _unknown(text: str) -> NormalizedConfig:
    return NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="u"),
                            raw_config=text, raw_lines=text.splitlines())


def test_a_confirmed_mapping_overrides_the_heuristic_for_its_predicate():
    config = _unknown("secure-shell protocol-version 2\n")
    config.ai_mappings.append(AIFieldMapping(
        line_number=1, raw_line="secure-shell protocol-version 2", normalized_field="management.ssh_version",
        extracted_value="1", confidence=0.95, confidence_tier="high", reasoning="", source="learned_mapping",
        final_value="1",
    ))
    result = next(r for r in evaluate_controls(config) if r.control_id == "MGMT-007")
    assert (result.status, result.assurance) == (Status.FAIL, Assurance.CONFIRMED)


def test_an_ai_mapping_that_contradicts_the_heuristic_is_unknown_citing_both():
    # Seen live: the AI read "legacy-access disabled" as Telnet off and hid the suspected Telnet FAIL
    config = _unknown("management-plane legacy-access disabled\n"
                      "remote-console state enabled\nremote-console protocol telnet\n")
    config.ai_mappings.append(AIFieldMapping(
        line_number=1, raw_line="management-plane legacy-access disabled", normalized_field="management.telnet_enabled",
        extracted_value="false", confidence=0.95, confidence_tier="high", reasoning="", source="ai_auto_mapped",
        final_value="false",
    ))
    result = next(r for r in evaluate_controls(config) if r.control_id == "MGMT-001")
    assert (result.status, result.evidence.line_numbers) == (Status.UNKNOWN, [1, 2, 3])
    assert "disagree" in result.reason


def test_heuristic_verdicts_are_never_scored():
    results = evaluate_controls(_unknown("remote-console state enabled\nremote-console protocol ssh telnet\n"
                                         "logging host 10.0.0.9\n"))
    assert {r.control_id: r.status for r in results if r.decided} == {"MGMT-001": Status.FAIL, "LOG-001": Status.PASS}
    assert calculate_posture([results]).posture is None


def test_confirmed_vendors_never_use_heuristics():
    text = (REPO / "backend" / "tests" / "fixtures" / "cisco_secure.cfg").read_text(encoding="utf-8")
    from app.parsers.detector import identify_vendor
    identification = identify_vendor(text)
    assert identification.confirmed
    assert all(r.assurance != Assurance.HEURISTIC for r in evaluate_controls(identification.config))
