"""
Phase 7 — AI escalation: only eligible UNKNOWN controls are judged (NOT_CONFIGURED ones as evidence discovery),
within a budget, cached only when useful, every citation verified against the cited line itself, every answer
bound to its control and never scored. The legacy line interpreter is isolated and never a default path.
"""

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import app.config as app_config
from app.ai import judge as J
from app.ai.interpretation_schemas import ConfidenceLevel, InterpretationResult, InterpretationStatus
from app.ai.client import StructuredResponse
from app.ai.judge import Budget, judge_config
from app.ai.redaction import redact_line
from app.analysis.engine import analyze
from app.analysis.scoring import calculate_posture
from app.api.routes.scan import get_scan_store
from app.controls.catalog import CONTROLS
from app.controls.evaluate import evaluate_controls
from app.db.database import get_connection
from app.facts.predicates import (
    IDLE_TIMEOUT, LOG_REMOTE_DESTINATION, LOGIN_BANNER, NTP_AUTHENTICATED, NTP_SERVER, PROTOCOL_ENABLED,
    SOURCE_RESTRICTED, SSH_VERSION, SecurityFact,
)
from app.main import app
from app.models.normalized import AIFieldMapping, DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, ControlResult, Evidence, Status
from app.parsers.detector import identify_vendor
from app.structure.tokenizer import tokenize

REPO = Path(__file__).resolve().parents[2]
UNKNOWN_CFG = (REPO / "sample" / "unknown.cfg").read_text(encoding="utf-8")


def _proposal(control_id, predicate, value, needles, evidence, subject=None, unit=None):
    """A proposal citing the excerpt lines that contain ``needles`` (None when the prompt lacks them)."""
    def build(prompt):
        refs = {text.strip(): int(ref) for ref, text in re.findall(r"^\[(\d+)\] (.*)$", prompt, re.M)}
        cited = [ref for needle in needles for text, ref in refs.items() if needle in text]
        if len(cited) < len(needles):
            return None
        return dict(control_id=control_id, predicate=predicate, subject=subject, value=value, unit=unit,
                    line_refs=cited, evidence=evidence, reasoning="test")
    return build


def _transport(*builders):
    def respond(**kwargs):
        proposals = [p for build in builders if (p := build(kwargs["prompt"]) if callable(build) else build)]
        return StructuredResponse(data={"proposals": proposals})
    return MagicMock(side_effect=respond)


def _scan(client, text, transport, name="unknown.cfg", ai=True):
    interpreter = MagicMock(return_value=[])
    with patch("app.api.routes.scan.interpret_lines", interpreter), \
         patch("app.api.routes.scan.is_available", return_value=ai), \
         patch("app.ai.judge.request_structured", transport):
        resp = client.post("/api/scan", files=[("files", (name, text.encode(), "text/plain"))])
    assert resp.status_code == 200, resp.text
    interpreter.assert_not_called()  # the legacy line interpreter is off by default
    return resp.json()


def _result(scan, control_id):
    return next(r for r in scan["results"] if r["control_id"] == control_id)


def _config(text):
    return NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="u"),
                            raw_config=text, raw_lines=text.splitlines())


def _unknown(*targets):
    return [ControlResult(control_id, Status.UNKNOWN, "undecided",
                          evidence=Evidence(line_numbers=list(n) if isinstance(n, tuple) else [n]))
            for control_id, n in targets]


def _judge(text, targets, *builders, budget=1):
    config, transport = _config(text), _transport(*builders)
    with patch("app.ai.judge.request_structured", transport):
        judge_config(config, _unknown(*targets), Budget(budget))
    return config, transport


UNRESTRICTED = _proposal("MGMT-003", SOURCE_RESTRICTED, "false", ["remote-console source-policy unrestricted"],
                         "source-policy unrestricted")


# ── verifier: the cited line must state the proposed setting ────────────────

ADVERSARIAL = """\
remote-console state enabled
remote-console protocol telnet
remote-console source-policy unrestricted
remote-console encryption disabled
remote-console http-proxy disabled

secure-shell protocol-version 2
secure-shell login-retries 1
secure-shell max-sessions 2

time-sync state enabled
time-sync server 10.44.70.10

operator inactivity-lock 600
operator idle-timeout 10 minutes

logging host 10.9.9.9
trusted-host 0.0.0.0
"""
ASKED = ("MGMT-001", "MGMT-002", "MGMT-003", "MGMT-006", "MGMT-007", "MGMT-009", "LOG-001", "LOG-002")


def _verify(proposal, text=ADVERSARIAL, asked=ASKED):
    raw = text.splitlines()
    statements = tokenize(raw)
    numbers = [n for n, line in enumerate(raw, 1) if line.strip()]
    shown = {n: raw[n - 1] for n in numbers}
    if callable(proposal):
        proposal = proposal("\n".join(f"[{ref}] {shown[n]}" for ref, n in enumerate(numbers, 1)))
        assert proposal is not None, "a cited needle is missing from the config: the case would pass vacuously"
    return J.verify(proposal, [CONTROLS[c] for c in asked], numbers, shown,
                    {s.line: s for s in statements}, J._readings(raw, statements), statements)


TELNET = ["remote-console state enabled", "remote-console protocol telnet"]


@pytest.mark.parametrize("proposal", [
    _proposal("MGMT-001", PROTOCOL_ENABLED, "true", TELNET, "protocol telnet", subject="telnet"),
    _proposal("MGMT-003", SOURCE_RESTRICTED, "false", ["source-policy unrestricted"], "source-policy unrestricted"),
    _proposal("MGMT-007", SSH_VERSION, "2", ["protocol-version 2"], "protocol-version 2"),
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["idle-timeout 10 minutes"], "idle-timeout 10 minutes", unit="min"),
    _proposal("LOG-001", LOG_REMOTE_DESTINATION, "10.9.9.9", ["logging host"], "logging host 10.9.9.9"),
], ids=["telnet", "unrestricted", "ssh-version", "idle-timeout", "log-host"])
def test_a_proposal_the_lexicon_reads_the_same_way_is_accepted(proposal):
    assert _verify(proposal) is not None


@pytest.mark.parametrize("proposal", [
    # unrelated disabled line
    _proposal("MGMT-003", SOURCE_RESTRICTED, "false", ["encryption disabled"], "encryption disabled"),
    # unrelated enabled line: a block's on switch is not NTP authentication
    _proposal("LOG-002", NTP_AUTHENTICATED, "true", ["time-sync state enabled"], "state enabled"),
    # unrelated numbers
    _proposal("MGMT-007", SSH_VERSION, "1", ["login-retries 1"], "login-retries 1"),
    _proposal("MGMT-007", SSH_VERSION, "2", ["max-sessions 2"], "max-sessions 2"),
    # a number of the right line smuggled in from another line of the block
    _proposal("MGMT-007", SSH_VERSION, "1", ["protocol-version 2", "login-retries 1"], "login-retries 1"),
    # wrong subject sharing a keyword
    _proposal("MGMT-002", PROTOCOL_ENABLED, "false", ["http-proxy disabled"], "http-proxy disabled", subject="http"),
    # a control asking about telnet cannot be answered about http
    _proposal("MGMT-001", PROTOCOL_ENABLED, "false", ["http-proxy disabled"], "http-proxy disabled", subject="http"),
    # hallucinated / malformed line references
    dict(control_id="MGMT-001", predicate=PROTOCOL_ENABLED, subject="telnet", value="true", unit=None,
         line_refs=[999], evidence="protocol telnet", reasoning=""),
    dict(control_id="MGMT-001", predicate=PROTOCOL_ENABLED, subject="telnet", value="true", unit=None,
         line_refs=[-1, 2], evidence="protocol telnet", reasoning=""),
    dict(control_id="MGMT-001", predicate=PROTOCOL_ENABLED, subject="telnet", value="true", unit=None,
         line_refs=[0], evidence="protocol telnet", reasoning=""),
    dict(control_id="MGMT-001", predicate=PROTOCOL_ENABLED, subject="telnet", value="true", unit=None,
         line_refs=[], evidence="protocol telnet", reasoning=""),
    "not a proposal",
    # wrong quoted evidence
    _proposal("MGMT-001", PROTOCOL_ENABLED, "true", TELNET, "protocol ssh", subject="telnet"),
    # contradicted polarity
    _proposal("MGMT-001", PROTOCOL_ENABLED, "false", TELNET, "protocol telnet", subject="telnet"),
    # another block's state line
    _proposal("MGMT-001", PROTOCOL_ENABLED, "true", ["time-sync state enabled", "remote-console protocol telnet"],
              "protocol telnet", subject="telnet"),
    # evidence across separate scopes, same value
    _proposal("MGMT-003", SOURCE_RESTRICTED, "false", ["source-policy unrestricted", "trusted-host 0.0.0.0"],
              "unrestricted"),
    # invented unit / a unit contradicting the line / another address
    _proposal("MGMT-006", IDLE_TIMEOUT, "600", ["inactivity-lock 600"], "inactivity-lock 600", unit="s"),
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["idle-timeout 10 minutes"], "idle-timeout 10", unit="s"),
    _proposal("LOG-001", LOG_REMOTE_DESTINATION, "10.1.1.1", ["logging host"], "logging host"),
    # predicate the control does not need / control not asked
    _proposal("MGMT-001", SSH_VERSION, "2", ["protocol-version 2"], "protocol-version 2"),
    _proposal("BOUNDARY-002", PROTOCOL_ENABLED, "true", TELNET, "protocol telnet", subject="telnet"),
], ids=[
    "unrelated-disabled", "unrelated-enabled", "unrelated-number-1", "unrelated-number-2", "smuggled-number",
    "shared-keyword", "other-control-subject", "hallucinated-999", "negative-ref", "zero-ref", "uncited",
    "not-a-dict", "wrong-quote", "reversed-polarity", "foreign-state-line", "separate-scopes", "invented-unit",
    "wrong-unit", "other-address", "predicate-not-needed", "control-not-asked",
])
def test_unverifiable_proposals_are_discarded(proposal):
    assert _verify(proposal) is None


# ── unfamiliar syntax: the lexicon does not read these lines ────────────────

UNFAMILIAR = """\
operator inactivity-lock 600
operator lock-after 10 minutes
operator max-sessions 10
operator lock-after 3 failures
operator session-limit 10 minutes

admin-gui allowed-networks 10.1.0.0/16
telnet-daemon off
telnet-client enabled
event-export target 10.7.7.7
"""


def test_the_lexicon_really_does_not_read_the_unfamiliar_lines():
    raw = UNFAMILIAR.splitlines()
    readings = J._readings(raw, tokenize(raw))
    assert set(readings) == {1}  # only `inactivity-lock 600` (no unit): every other line is new vocabulary


@pytest.mark.parametrize("proposal", [
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["lock-after 10 minutes"], "lock-after 10 minutes", unit="min"),
    # a live model spells the unit out; the line still has to write a minutes word
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["lock-after 10 minutes"], "lock-after 10 minutes", unit="minutes"),
    _proposal("MGMT-003", SOURCE_RESTRICTED, "true", ["allowed-networks"], "allowed-networks 10.1.0.0/16"),
    _proposal("MGMT-001", PROTOCOL_ENABLED, "false", ["telnet-daemon off"], "telnet-daemon off", subject="telnet"),
    _proposal("LOG-001", LOG_REMOTE_DESTINATION, "10.7.7.7", ["event-export target"], "target 10.7.7.7"),
], ids=["lock-after-minutes", "unit-spelled-out", "allowed-networks", "telnet-daemon", "event-export"])
def test_an_unfamiliar_but_obvious_setting_is_accepted_when_the_line_states_the_value(proposal):
    assert _verify(proposal, UNFAMILIAR) is not None


@pytest.mark.parametrize("proposal", [
    # unrelated numbers never become an idle timeout, with or without an invented unit
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["max-sessions 10"], "max-sessions 10", unit="min"),
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["max-sessions 10"], "max-sessions 10"),
    _proposal("MGMT-006", IDLE_TIMEOUT, "3", ["lock-after 3 failures"], "lock-after 3 failures", unit="min"),
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["session-limit 10 minutes"], "session-limit 10 minutes", unit="min"),
    # related words, but the value is not the line's
    _proposal("MGMT-006", IDLE_TIMEOUT, "15", ["lock-after 10 minutes"], "lock-after", unit="min"),
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["lock-after 10 minutes"], "lock-after 10", unit="h"),
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["lock-after 10 minutes"], "lock-after 10"),  # no unit claimed
    _proposal("MGMT-003", SOURCE_RESTRICTED, "false", ["allowed-networks"], "allowed-networks"),
    _proposal("MGMT-001", PROTOCOL_ENABLED, "true", ["telnet-daemon off"], "telnet-daemon", subject="telnet"),
    # a client is not the management server
    _proposal("MGMT-001", PROTOCOL_ENABLED, "true", ["telnet-client enabled"], "telnet-client enabled", subject="telnet"),
    # the value must be on the line: 600 s is the AI's arithmetic on `10 minutes`, not a stated value
    _proposal("MGMT-006", IDLE_TIMEOUT, "600", ["lock-after 10 minutes"], "10 minutes", unit="s"),
    # a spelled-out unit the line does not write
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["lock-after 10 minutes"], "lock-after 10", unit="seconds"),
    # the lexicon reads `inactivity-lock 600` without a unit: the AI cannot add one
    _proposal("MGMT-006", IDLE_TIMEOUT, "600", ["inactivity-lock 600"], "inactivity-lock 600", unit="s"),
    # cross-control: an idle-timeout line never answers the source restriction or SSH questions
    _proposal("MGMT-003", SOURCE_RESTRICTED, "true", ["lock-after 10 minutes"], "lock-after"),
    _proposal("MGMT-007", SSH_VERSION, "10", ["lock-after 10 minutes"], "lock-after 10"),
    # an unfamiliar line cited next to another block's line
    _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["lock-after 10 minutes", "admin-gui allowed-networks"], "lock-after 10",
              unit="min"),
], ids=[
    "max-sessions-with-unit", "max-sessions", "lockout-failures", "session-limit", "other-number", "wrong-unit",
    "no-unit", "contradicted-address", "contradicted-polarity", "client", "converted-unit", "spelled-wrong-unit", "lexicon-reading-wins",
    "idle-line-for-source", "idle-line-for-ssh", "two-scopes",
])
def test_unrelated_or_unstated_unfamiliar_readings_are_rejected(proposal):
    assert _verify(proposal, UNFAMILIAR) is None


LOCK = "operator inactivity-lock 600\noperator lock-after 10 minutes\n"
LOCK_AFTER = _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["lock-after 10 minutes"], "lock-after 10 minutes", unit="min")


def test_lock_after_becomes_a_proposed_idle_timeout_never_a_decision():
    client = TestClient(app)
    off = _scan(client, LOCK, _transport(), ai=False)
    transport = _transport(LOCK_AFTER)
    on = _scan(client, LOCK, transport)

    assert transport.call_count == 1
    prompt = transport.call_args.kwargs["prompt"]
    assert "MGMT-006" in prompt and "operator lock-after 10 minutes" in prompt and "scope: operator" in prompt
    before, after = _result(off, "MGMT-006"), _result(on, "MGMT-006")
    assert (before["status"], before["proposed_status"]) == ("unknown", None)
    assert [after[k] for k in ("status", "assurance", "proposed_status")] == ["unknown", "ai_verified", "pass"]
    assert 2 in after["evidence"]["line_numbers"] and "AI proposes PASS" in after["reason"]
    scored = ("score", "total_findings", "posture", "coverage", "posture_bounds")
    assert {k: on[k] for k in scored} == {k: off[k] for k in scored} and on["devices"] == off["devices"]
    # cross-control: every other control reads exactly as without the AI
    others = lambda scan: {r["control_id"]: (r["status"], r["proposed_status"]) for r in scan["results"]
                           if r["control_id"] != "MGMT-006"}
    assert others(on) == others(off)

    config = get_scan_store()[on["scan_id"]]["configs"][0]
    assert [(f.control_id, f.value, f.evidence.line_numbers) for f in config.ai_facts] == [("MGMT-006", 10.0, [2])]


def test_max_sessions_never_becomes_an_idle_timeout_end_to_end():
    text = "operator inactivity-lock 600\noperator max-sessions 10\n"
    wrong = _proposal("MGMT-006", IDLE_TIMEOUT, "10", ["max-sessions 10"], "max-sessions 10", unit="min")
    config, transport = _judge(text, [("MGMT-006", 1)], wrong)
    assert transport.call_count == 1 and config.ai_facts == []
    assert "verifiable citation" in config.ai_notes["MGMT-006"]


def test_a_control_without_usable_evidence_sends_only_a_few_related_scopes():
    text = ("hostname-label EDGE\nbackup-schedule daily 02:00\n\nadmin-gui allowed-networks 10.1.0.0/16\n"
            "admin-gui theme dark\n\nsnmp-agent location lab\n")
    transport = _transport(_proposal("MGMT-003", SOURCE_RESTRICTED, "true", ["allowed-networks"], "allowed-networks"))
    scan = _scan(TestClient(app), text, transport)
    excerpt = transport.call_args.kwargs["prompt"].split("CONFIGURATION EXCERPT")[1]
    assert "allowed-networks" in excerpt and "theme dark" in excerpt  # the related line's scope
    assert "backup-schedule" not in excerpt and "snmp-agent" not in excerpt and "hostname-label" not in excerpt
    mgmt003 = _result(scan, "MGMT-003")
    assert [mgmt003[k] for k in ("status", "assurance", "proposed_status")] == ["unknown", "ai_verified", "pass"]
    assert scan["score"] is None and scan["coverage"] == 0


def test_a_secret_in_unfamiliar_syntax_stays_redacted():
    text = ("operator inactivity-lock 600\noperator lock-after 10 minutes\n"
            "operator unlock-passphrase Hunter2Secret\noperator lock-banner Hunter2Secret\n")
    _, transport = _judge(text, [("MGMT-006", 1)], LOCK_AFTER)
    prompt = transport.call_args.kwargs["prompt"]
    assert "operator unlock-passphrase" in prompt and "operator lock-banner" in prompt
    assert "Hunter2Secret" not in prompt


def test_the_judge_discards_an_unrelated_citation_end_to_end():
    config, transport = _judge(UNKNOWN_CFG, [("MGMT-003", (67, 68, 72))],
                               _proposal("MGMT-003", SOURCE_RESTRICTED, "false", ["remote-console encryption disabled"],
                                         "encryption disabled"))
    assert transport.call_count == 1
    assert config.ai_facts == [] and "verifiable citation" in config.ai_notes["MGMT-003"]


# ── scopes and eligibility ──────────────────────────────────────────────────

NO_BLANK_LINES = """\
interface mgmt0
 trusted-host 0.0.0.0
 description admin access
interface console
 source-policy unrestricted
"""


def test_excerpt_is_the_tokenizer_scope_not_a_blank_line_paragraph():
    _, transport = _judge(NO_BLANK_LINES, [("MGMT-003", 2)])
    excerpt = transport.call_args.kwargs["prompt"].split("CONFIGURATION EXCERPT")[1]
    assert "interface mgmt0" in excerpt and "trusted-host" in excerpt
    assert "interface console" not in excerpt and "source-policy" not in excerpt


def test_lines_of_two_scopes_never_form_one_evidence_block():
    both = _proposal("MGMT-003", SOURCE_RESTRICTED, "false", ["trusted-host 0.0.0.0", "source-policy unrestricted"],
                     "unrestricted")
    config, _ = _judge(NO_BLANK_LINES, [("MGMT-003", (2, 5))], both)
    assert config.ai_facts == []

    one = _proposal("MGMT-003", SOURCE_RESTRICTED, "false", ["source-policy unrestricted"], "unrestricted")
    config, _ = _judge(NO_BLANK_LINES, [("MGMT-003", (2, 5))], one)
    assert [(f.value, f.evidence.line_numbers) for f in config.ai_facts] == [(False, [5])]


def test_only_unknown_controls_with_a_related_line_are_escalated():
    config = _config("remote-console state enabled\nremote-console protocol telnet\nremote-console encryption disabled\n"
                     "snmp-server community c0mm RO\n")
    transport = _transport()
    results = [
        ControlResult("MGMT-001", Status.FAIL, "decided", evidence=Evidence(line_numbers=[2])),
        ControlResult("MGMT-006", Status.UNKNOWN, "no related line anywhere", evidence=Evidence(line_numbers=[3])),
        ControlResult("MGMT-004", Status.UNKNOWN, "not an AI predicate", evidence=Evidence(line_numbers=[4])),
        ControlResult("MGMT-009", Status.UNKNOWN, "no evidence, no banner line"),
    ]
    with patch("app.ai.judge.request_structured", transport):
        judge_config(config, results, Budget(5))
    transport.assert_not_called()


def test_confirmed_vendors_are_never_escalated():
    cisco = (REPO / "backend" / "tests" / "fixtures" / "cisco_secure.cfg").read_text(encoding="utf-8")
    transport = _transport()
    _scan(TestClient(app), cisco, transport, name="cisco.cfg")
    transport.assert_not_called()


# ── AI facts are bound to their control and never decisive ──────────────────

def _ai_fact(predicate, value, control_id, subject=None, line=1):
    return SecurityFact(predicate, value, Assurance.AI_VERIFIED, Evidence(line_numbers=[line], text=["x"]),
                        subject=subject, control_id=control_id)


def test_an_ai_fact_is_read_only_by_the_control_that_asked():
    config = _config("web-console mode legacy\n")
    config.ai_facts = [_ai_fact(PROTOCOL_ENABLED, False, "MGMT-001", subject="http")]
    results = {r.control_id: r for r in evaluate_controls(config)}
    assert results["MGMT-002"].status == Status.NOT_CONFIGURED  # an http fact asked by MGMT-001 never answers MGMT-002

    config.ai_facts = [_ai_fact(PROTOCOL_ENABLED, False, "MGMT-002", subject="http")]
    results = {r.control_id: r for r in evaluate_controls(config)}
    assert (results["MGMT-002"].status, results["MGMT-002"].proposed_status) == (Status.UNKNOWN, Status.PASS)
    assert results["MGMT-001"].status == Status.NOT_CONFIGURED


def test_judge_facts_carry_the_asking_control():
    config, _ = _judge(UNKNOWN_CFG, [("MGMT-003", (67, 68, 72))], UNRESTRICTED)
    assert [(f.control_id, f.predicate, f.value) for f in config.ai_facts] == [("MGMT-003", SOURCE_RESTRICTED, False)]


@pytest.mark.parametrize("value,proposed", [(True, Status.PASS), (False, Status.FAIL)])
def test_ai_pass_or_fail_never_changes_posture_score_findings_or_assessed(value, proposed):
    config = _config("audit-stream collector-a\n")
    baseline = analyze(config)
    config.ai_facts = [_ai_fact(PROTOCOL_ENABLED, not value, "MGMT-001", subject="telnet")]

    result = analyze(config)
    mgmt001 = next(r for r in result.device_results[0] if r.control_id == "MGMT-001")
    assert (mgmt001.status, mgmt001.proposed_status, mgmt001.assurance) == (Status.UNKNOWN, proposed,
                                                                           Assurance.AI_VERIFIED)
    assert mgmt001.failure is None and mgmt001.evidence.line_numbers == [1]
    assert (result.score, result.findings, result.devices[0]["assessed"]) == (None, [], False)
    assert (result.critical_count, result.high_count, result.medium_count, result.low_count) == (0, 0, 0, 0)
    posture = calculate_posture(result.device_results)
    assert (posture.posture, posture.coverage) == (None, 0)
    assert (baseline.score, baseline.devices[0]["assessed"]) == (None, False)


def test_ai_fail_changes_nothing_scored_through_the_scan_api():
    client = TestClient(app)
    off = _scan(client, UNKNOWN_CFG, _transport(), ai=False)
    on = _scan(client, UNKNOWN_CFG, _transport(UNRESTRICTED))

    mgmt003 = _result(on, "MGMT-003")
    assert [mgmt003[k] for k in ("status", "assurance", "proposed_status")] == ["unknown", "ai_verified", "fail"]
    assert 72 in mgmt003["evidence"]["line_numbers"]
    scored = ("score", "total_findings", "critical", "high", "medium", "low", "posture", "coverage", "posture_bounds")
    assert {k: on[k] for k in scored} == {k: off[k] for k in scored}
    assert on["findings"] == off["findings"] and on["devices"] == off["devices"]
    assert {r["control_id"]: r["status"] for r in on["results"]} == {r["control_id"]: r["status"] for r in off["results"]}


def test_ai_mapping_on_a_confirmed_vendor_is_a_proposal_not_a_finding():
    text = (REPO / "backend" / "tests" / "fixtures" / "cisco_secure.cfg").read_text(encoding="utf-8")
    config = identify_vendor(text + "\nsecure-shell protocol-version 1\n").config
    line = len(config.raw_lines)
    config.management.ssh_version = 1
    config.management.source_lines.append(line)
    config.ai_mappings.append(AIFieldMapping(line_number=line, raw_line=config.raw_lines[line - 1],
                                             normalized_field="management.ssh_version", extracted_value="1",
                                             confidence=0.95, confidence_tier="high", reasoning="",
                                             source="ai_auto_mapped", final_value="1"))
    result = analyze(config)
    mgmt007 = next(r for r in result.device_results[0] if r.control_id == "MGMT-007")
    assert (mgmt007.status, mgmt007.proposed_status) == (Status.UNKNOWN, Status.FAIL)
    assert "MGMT-007" not in {f.rule_id for f in result.findings} and result.score == 100


# ── scan API, budget, cache ─────────────────────────────────────────────────

def test_unknown_cfg_one_call_then_cache_hits_across_the_fleet():
    client = TestClient(app)
    transport = _transport(UNRESTRICTED)
    first = _scan(client, UNKNOWN_CFG, transport)

    assert transport.call_count == 1
    assert (first["adaptive"]["ai_calls"], first["adaptive"]["ai_cache_hits"]) == (1, 0)
    prompt = transport.call_args.kwargs["prompt"]
    assert "MGMT-003" in prompt and "MGMT-006" in prompt and "MGMT-001" not in prompt  # decided controls never go
    mgmt006 = _result(first, "MGMT-006")
    assert mgmt006["status"] == "unknown" and "verifiable citation" in mgmt006["reason"]
    assert first["coverage"] == 0

    # Same device again, and a fleet copy whose lines are shifted: identical scopes, zero calls
    silent = MagicMock(side_effect=AssertionError("cached"))
    again = _scan(client, UNKNOWN_CFG, silent)
    shifted = _scan(client, "! fleet copy\n\n" + UNKNOWN_CFG, silent)
    silent.assert_not_called()
    assert (again["adaptive"]["ai_calls"], again["adaptive"]["ai_cache_hits"]) == (0, 1)
    assert _result(again, "MGMT-003")["proposed_status"] == "fail"
    assert 74 in _result(shifted, "MGMT-003")["evidence"]["line_numbers"]


def test_budget_exhausted_leaves_controls_unknown_with_a_reason(monkeypatch):
    monkeypatch.setattr(app_config.settings, "ai_judge_max_calls_per_scan", 0)
    transport = _transport(UNRESTRICTED)
    scan = _scan(TestClient(app), UNKNOWN_CFG, transport)
    transport.assert_not_called()
    result = _result(scan, "MGMT-003")
    assert result["status"] == "unknown" and result["proposed_status"] is None and "budget" in result["reason"]


FIVE_TARGETS = (("MGMT-001", 71), ("MGMT-003", 72), ("MGMT-007", 32), ("LOG-001", 55), ("MGMT-006", 38))


def test_budget_spans_chunks():
    config, transport = _judge(UNKNOWN_CFG, FIVE_TARGETS)
    assert transport.call_count == 1  # four controls per call, most severe first
    assert "budget" in config.ai_notes["MGMT-006"] and "verifiable" in config.ai_notes["MGMT-001"]


def test_exhausted_quota_stops_further_calls_and_is_not_cached():
    config = _config(UNKNOWN_CFG)
    budget = Budget(3)
    down = MagicMock(return_value=StructuredResponse(error="quota_exhausted"))
    with patch("app.ai.judge.request_structured", down):
        judge_config(config, _unknown(*FIVE_TARGETS), budget)
    assert down.call_count == 1 and budget.remaining == 0
    assert "unavailable (quota_exhausted)" in config.ai_notes["MGMT-001"] and "budget" in config.ai_notes["MGMT-006"]
    assert config.ai_facts == []

    _, back = _judge(UNKNOWN_CFG, FIVE_TARGETS, budget=2)
    assert back.call_count == 2  # the failed call left nothing in the cache


@pytest.mark.parametrize("answer", [
    StructuredResponse(data={"proposals": []}),
    StructuredResponse(data={"proposals": ["junk", {"control_id": "MGMT-003"}]}),
    StructuredResponse(data={"proposals": {"not": "a list"}}),
    StructuredResponse(error="invalid_output"),
], ids=["empty", "all-rejected", "malformed", "invalid-output"])
def test_useless_answers_are_never_cached(answer):
    for _ in range(2):
        config, transport = _config(UNKNOWN_CFG), MagicMock(return_value=answer)
        with patch("app.ai.judge.request_structured", transport):
            judge_config(config, _unknown(("MGMT-003", 72)), Budget(1))
        assert transport.call_count == 1 and config.ai_facts == []
    with get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM ai_judge_cache").fetchone()[0] == 0


def test_cached_answers_are_reverified_and_a_bad_one_is_asked_again():
    _judge(UNKNOWN_CFG, [("MGMT-003", 72)], UNRESTRICTED)
    config, silent = _judge(UNKNOWN_CFG, [("MGMT-003", 72)])  # served from the cache
    assert silent.call_count == 0 and config.ai_facts

    with get_connection() as conn:
        conn.execute("UPDATE ai_judge_cache SET response = replace(response, '\"false\"', '\"true\"')")
    config, fresh = _judge(UNKNOWN_CFG, [("MGMT-003", 72)], UNRESTRICTED)
    assert fresh.call_count == 1  # the poisoned entry verified to nothing: not a hit, asked again
    assert [(f.value, f.evidence.line_numbers) for f in config.ai_facts] == [(False, [72])]


# ── training ────────────────────────────────────────────────────────────────

def test_verified_ai_line_can_be_confirmed_into_a_recognizer():
    client = TestClient(app)
    text = "operator inactivity-lock 600\noperator idle-timeout 10 minutes\n"
    transport = _transport(_proposal("MGMT-006", IDLE_TIMEOUT, "10", ["idle-timeout 10 minutes"], "10 minutes",
                                     unit="min"))
    scan = _scan(client, text, transport)
    assert transport.call_count == 1

    queue = client.get(f"/api/adaptive/scans/{scan['scan_id']}/provisional").json()["items"]
    lines = {line["line_number"] for item in queue if item["control_id"] == "MGMT-006" for line in item["lines"]}
    assert lines == {1, 2}
    draft = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers/draft",
                        json={"control_id": "MGMT-006", "line_number": 2}).json()
    assert draft["draft"]["command_pattern"].startswith("operator idle-timeout {duration")


def test_rejected_or_hallucinated_ai_evidence_never_reaches_training():
    client = TestClient(app)
    hallucinated = dict(control_id="MGMT-003", predicate=SOURCE_RESTRICTED, subject=None, value="false", unit=None,
                        line_refs=[9999], evidence="source-policy unrestricted", reasoning="")
    unrelated = _proposal("MGMT-003", SOURCE_RESTRICTED, "false", ["remote-console encryption disabled"],
                          "encryption disabled")
    scan = _scan(client, UNKNOWN_CFG, _transport(hallucinated, unrelated))
    config = get_scan_store()[scan["scan_id"]]["configs"][0]
    assert config.ai_facts == []

    queue = client.get(f"/api/adaptive/scans/{scan['scan_id']}/provisional").json()["items"]
    queued = {line["line_number"] for item in queue for line in item["lines"]}
    assert 73 not in queued and 9999 not in queued
    for line in (73, 9999):
        draft = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers/draft",
                            json={"control_id": "MGMT-003", "line_number": line})
        assert draft.status_code == 404
        reject = client.post(f"/api/adaptive/scans/{scan['scan_id']}/provisional/reject",
                             json={"control_id": "MGMT-003", "line_number": line})
        assert reject.status_code == 404


# ── secrets ─────────────────────────────────────────────────────────────────

def test_verified_proposals_become_ai_verified_facts():
    config = _config(UNKNOWN_CFG + "\nadmin-session idle-timeout 900s\n")
    lock = len(config.raw_lines)
    transport = _transport(
        _proposal("MGMT-001", PROTOCOL_ENABLED, "true", ["remote-console state enabled", "remote-console protocol telnet"],
                  "protocol telnet", subject="telnet"),
        _proposal("LOG-001", LOG_REMOTE_DESTINATION, "10.44.60.20", ["audit-stream destination"], "destination 10.44.60.20"),
        _proposal("MGMT-006", IDLE_TIMEOUT, "900", ["idle-timeout 900s"], "900s", unit="s"),
    )
    with patch("app.ai.judge.request_structured", transport):
        judge_config(config, _unknown(("MGMT-001", 71), ("LOG-001", 55), ("MGMT-006", lock)), Budget(2))

    facts = {f.predicate: f for f in config.ai_facts}
    assert {f.assurance for f in config.ai_facts} == {Assurance.AI_VERIFIED}
    assert (facts[PROTOCOL_ENABLED].value, facts[PROTOCOL_ENABLED].evidence.line_numbers) == (True, [70, 71])
    assert facts[PROTOCOL_ENABLED].control_id == "MGMT-001"
    assert facts[LOG_REMOTE_DESTINATION].value == ["10.44.60.20"]
    assert (facts[IDLE_TIMEOUT].value, facts[IDLE_TIMEOUT].unit) == (15.0, "min")
    assert transport.call_count == 1 and config.ai_notes == {}


UNKNOWN_VENDOR_SECRETS = [
    ("snmp-community {} ro", "LeakSnmp01"),
    ("snmp community-string {}", "LeakSnmp02"),
    ("admin-credential {}", "LeakCred03"),
    ("local-user admin passcode {}", "LeakCode04"),
    ("api-token {}", "LeakTok05"),
    ("access-token={}", "LeakTok06"),
    ("user admin hash {}", "LeakHash07"),
    ("auth-string {}", "LeakAuth08"),
    ("login pwd {}", "LeakPwd09"),
    ("enable-pass {}", "LeakPass10"),
    ("user admin credentials {}", "LeakCred11"),
    ("bgp neighbor 10.0.0.1 remote-as 65001 md5 {}", "LeakMd5x12"),
]


@pytest.mark.parametrize("syntax,secret", UNKNOWN_VENDOR_SECRETS)
def test_unknown_vendor_secret_syntax_is_redacted(syntax, secret):
    assert secret not in redact_line(syntax.format(secret))


def test_no_secret_reaches_the_prompt_neither_its_own_line_nor_a_neighbour():
    block = ["remote-console state enabled", "remote-console protocol telnet",
             "remote-console password S3cr3tValue!", "remote-console banner S3cr3tValue!",
             *(f"remote-console {syntax.format(secret)}" for syntax, secret in UNKNOWN_VENDOR_SECRETS)]
    _, transport = _judge("\n".join(block) + "\n", [("MGMT-001", 2)])
    prompt = transport.call_args.kwargs["prompt"]
    assert "remote-console banner" in prompt  # the neighbour was sent, without the reused value
    for secret in ["S3cr3tValue!", *(s for _, s in UNKNOWN_VENDOR_SECRETS)]:
        assert secret not in prompt, secret


# ── NOT_CONFIGURED: evidence discovery ──────────────────────────────────────

PANOS = """\
set deviceconfig system hostname fw01.corp.example
set deviceconfig system dns-setting servers primary 10.0.0.53
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 0.pool.ntp.org
set deviceconfig system ntp-servers primary-ntp-server authentication-type none
set deviceconfig system ntp-servers primary-ntp-server authentication-key Ntp5ecretKey

set network interface ethernet ethernet1/1 layer3 ip 198.51.100.2/30
set rulebase security rules allow-web action allow
set shared admin-password Adm1nS3cret

logging host 10.9.9.9
"""
NTP_HOSTNAME = _proposal("LOG-002", NTP_SERVER, "0.pool.ntp.org", ["ntp-server-address"],
                         "ntp-server-address 0.pool.ntp.org")
SCORED = ("score", "total_findings", "critical", "high", "medium", "low", "posture", "coverage", "posture_bounds")


def _others(scan, control_id):
    return {r["control_id"]: (r["status"], r["assurance"], r["proposed_status"]) for r in scan["results"]
            if r["control_id"] != control_id}


def test_panos_ntp_hostname_is_discovered_but_never_decides_the_control():
    client = TestClient(app)
    off = _scan(client, PANOS, _transport(), ai=False)
    transport = _transport(NTP_HOSTNAME)
    on = _scan(client, PANOS, transport)

    assert transport.call_count == 1
    prompt = transport.call_args.kwargs["prompt"]
    assert "LOG-002" in prompt and "task: discover" in prompt
    excerpt = prompt.split("CONFIGURATION EXCERPT")[1]
    assert "ntp-server-address 0.pool.ntp.org" in excerpt
    # only the related tokenizer scope: other blocks never travel, secrets never do
    assert "rulebase" not in excerpt and "ethernet1/1" not in excerpt and "logging host" not in excerpt
    assert "Ntp5ecretKey" not in prompt and "Adm1nS3cret" not in prompt

    before, after = _result(off, "LOG-002"), _result(on, "LOG-002")
    assert (before["status"], before["proposed_status"]) == ("not_configured", None)
    # a server is not authentication: the discovered fact leaves the control UNKNOWN with no proposed verdict
    assert [after[k] for k in ("status", "assurance", "proposed_status")] == ["unknown", None, None]
    assert after["evidence"]["line_numbers"] == [3] and "authentication" in after["reason"]
    assert {k: on[k] for k in SCORED} == {k: off[k] for k in SCORED}
    assert on["findings"] == off["findings"] and on["devices"] == off["devices"]
    assert _others(on, "LOG-002") == _others(off, "LOG-002")

    config = get_scan_store()[on["scan_id"]]["configs"][0]
    assert [(f.control_id, f.predicate, f.value, f.assurance, f.evidence.line_numbers) for f in config.ai_facts] == \
        [("LOG-002", NTP_SERVER, ["0.pool.ntp.org"], Assurance.AI_VERIFIED, [3])]


def test_a_discovered_banner_is_a_proposed_pass_that_changes_nothing_scored():
    text = 'login-message "Authorized access only"\n\nlogging host 10.9.9.9\n'
    client = TestClient(app)
    off = _scan(client, text, _transport(), ai=False)
    transport = _transport(_proposal("MGMT-009", LOGIN_BANNER, "true", ["login-message"],
                                     'login-message "Authorized access only"'))
    on = _scan(client, text, transport)

    assert "task: discover" in transport.call_args.kwargs["prompt"]
    assert [_result(off, "MGMT-009")[k] for k in ("status", "assurance", "proposed_status")] == \
        ["not_configured", None, None]
    after = _result(on, "MGMT-009")
    assert [after[k] for k in ("status", "assurance", "proposed_status")] == ["unknown", "ai_verified", "pass"]
    assert {k: on[k] for k in SCORED} == {k: off[k] for k in SCORED}
    assert on["findings"] == off["findings"] and on["devices"] == off["devices"]
    assert _others(on, "MGMT-009") == _others(off, "MGMT-009")


def test_discovery_without_a_verified_citation_keeps_not_configured():
    client = TestClient(app)
    unverifiable = _proposal("LOG-002", NTP_SERVER, "1.pool.ntp.org", ["ntp-server-address"], "ntp-server-address")
    scan = _scan(client, PANOS, _transport(unverifiable))
    result = _result(scan, "LOG-002")
    assert (result["status"], result["proposed_status"], result["reason"]) == \
        ("not_configured", None, "No relevant setting was found in this configuration")
    assert get_scan_store()[scan["scan_id"]]["configs"][0].ai_facts == []


def test_absence_is_never_evidence():
    # nothing to cite: an empty config (or one without related lines) is never sent, never passes
    for text in ("", "hostname-label EDGE\nbackup-schedule daily 02:00\n"):
        config, transport = _config(text), _transport()
        results = evaluate_controls(config)
        with patch("app.ai.judge.request_structured", transport):
            judge_config(config, results, Budget(5))
        transport.assert_not_called()
        assert config.ai_facts == []
        assert Status.PASS not in {r.status for r in evaluate_controls(config)}

    # a proposal claiming a setting from absence cites nothing, or a line that does not state it
    absent = dict(control_id="LOG-002", predicate=NTP_SERVER, subject=None, value="0.pool.ntp.org", unit=None,
                  line_refs=[], evidence="no ntp server is configured", reasoning="absent")
    assert _verify(absent, PANOS) is None
    assert _verify(_proposal("MGMT-009", LOGIN_BANNER, "true", ["system hostname"], "hostname fw01.corp.example"),
                   PANOS) is None


def test_the_discovered_hostname_verifies():
    assert _verify(NTP_HOSTNAME, PANOS) is not None


@pytest.mark.parametrize("proposal", [
    # NTP server presence is not NTP authentication
    _proposal("LOG-002", NTP_AUTHENTICATED, "true", ["ntp-server-address"], "ntp-server-address 0.pool.ntp.org"),
    # `authentication-type none` states no on/off value
    _proposal("LOG-002", NTP_AUTHENTICATED, "false", ["authentication-type none"], "authentication-type none"),
    # unrelated hostname / address lines
    _proposal("LOG-002", NTP_SERVER, "fw01.corp.example", ["system hostname"], "hostname fw01.corp.example"),
    _proposal("LOG-002", NTP_SERVER, "10.0.0.53", ["dns-setting"], "primary 10.0.0.53"),
    # a hostname the cited line does not hold
    _proposal("LOG-002", NTP_SERVER, "1.pool.ntp.org", ["ntp-server-address"], "ntp-server-address"),
    # a keyword of the line is not a host
    _proposal("LOG-002", NTP_SERVER, "primary-ntp-server", ["ntp-server-address"], "primary-ntp-server"),
    # cross-control: the NTP line never answers remote logging, and LOG-002 never takes the log host
    _proposal("LOG-001", LOG_REMOTE_DESTINATION, "0.pool.ntp.org", ["ntp-server-address"], "0.pool.ntp.org"),
    _proposal("LOG-002", NTP_SERVER, "10.9.9.9", ["logging host"], "logging host 10.9.9.9"),
    # the NTP block's secret line is not a server
    _proposal("LOG-002", NTP_SERVER, "ntp5ecretkey", ["authentication-key"], "authentication-key"),
], ids=["server-is-not-auth", "no-polarity", "hostname-line", "dns-line", "other-host", "keyword", "ntp-for-log",
        "log-for-ntp", "secret-line"])
def test_unrelated_discoveries_are_rejected(proposal):
    assert _verify(proposal, PANOS) is None


def test_discovery_never_displaces_an_unknown_control():
    results = [*_unknown(*FIVE_TARGETS), ControlResult("LOG-002", Status.NOT_CONFIGURED, "nothing found")]
    config, transport = _config(UNKNOWN_CFG), _transport()
    with patch("app.ai.judge.request_structured", transport):
        judge_config(config, results, Budget(1))
    assert transport.call_count == 1 and "task: discover" not in transport.call_args.kwargs["prompt"]
    assert "budget" in config.ai_notes["LOG-002"]


# ── legacy interpreter: isolated, never a default path ──────────────────────

def test_the_legacy_interpreter_is_not_a_default_path():
    defaults = app_config.Settings(_env_file=None)
    assert defaults.adaptive_ai_for_known_vendors is False
    assert not hasattr(defaults, "ai_legacy_line_interpreter")  # the unknown-vendor legacy switch is gone


def test_unknown_vendors_never_reach_the_legacy_interpreter_even_when_it_is_enabled(monkeypatch):
    monkeypatch.setattr(app_config.settings, "adaptive_ai_for_known_vendors", True)
    transport = _transport(UNRESTRICTED)
    scan = _scan(TestClient(app), UNKNOWN_CFG, transport)  # asserts the legacy interpreter is not called
    assert transport.call_count == 1 and scan["adaptive"]["interpretations"] == []


def _legacy_high(lines):
    return [InterpretationResult(
        line_number=ln.line_number, raw_line=ln.raw_line, likely_vendor="cisco_ios", security_concept="ssh",
        normalized_field="management.ssh_version", extracted_value="1", value_evidence="protocol-version 1",
        confidence=ConfidenceLevel.HIGH, numeric_confidence=0.97, reasoning="SSH version",
        status=InterpretationStatus.INTERPRETED,
    ) for ln in lines if "secure-shell" in ln.raw_line]


def test_legacy_known_vendor_interpreter_only_fills_the_review_queue(monkeypatch):
    text = (REPO / "backend" / "tests" / "fixtures" / "cisco_secure.cfg").read_text(encoding="utf-8") \
        + "\nsecure-shell protocol-version 1\n"
    client = TestClient(app)
    interpreter = MagicMock(side_effect=_legacy_high)

    def scan():
        with patch("app.api.routes.scan.interpret_lines", interpreter), \
             patch("app.api.routes.scan.is_available", return_value=True), \
             patch("app.ai.judge.request_structured", MagicMock(side_effect=AssertionError("judge"))):
            resp = client.post("/api/scan", files=[("files", ("cisco.cfg", text.encode(), "text/plain"))])
        assert resp.status_code == 200, resp.text
        return resp.json()

    default = scan()
    interpreter.assert_not_called()  # off by default, even with AI available

    monkeypatch.setattr(app_config.settings, "adaptive_ai_for_known_vendors", True)
    legacy = scan()
    assert interpreter.call_count == 1 and legacy["devices"][0]["vendor"] == "cisco_ios"
    record = next(m for m in legacy["adaptive"]["ai_mappings"] if "secure-shell" in m["raw_line"])
    # a valid HIGH interpretation with cited evidence is still never applied without an administrator
    assert (record["source"], record["confidence_tier"]) == ("needs_review", "high")
    assert "administrator review" in record["reason"]

    stored = lambda s: get_scan_store()[s["scan_id"]]["configs"][0]
    assert stored(legacy).management.ssh_version == stored(default).management.ssh_version
    view = lambda s: [(r["control_id"], r["status"], r["assurance"], r["proposed_status"], r["evidence"])
                      for r in s["results"]]
    assert view(legacy) == view(default)
    assert {k: legacy[k] for k in SCORED} == {k: default[k] for k in SCORED}
    assert legacy["findings"] == default["findings"] and legacy["devices"] == default["devices"]
