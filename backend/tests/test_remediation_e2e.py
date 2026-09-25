"""
Phase 8 -remediation v2: deterministic, vendor-aware, verified by a full rescan.

Replaces the pre-Phase 8 tests that required every sample to rescan at 100 with 0 findings.
That was only reachable with placeholder values (``$9$REMEDIATED_HASH``, ``10.0.0.100``) and
by rewriting any-to-any rules to invented address objects -exactly what Phase 8 removes.
The new invariants: a FIXED control really passes on rescan, nothing else regresses, the
vendor stays confirmed, output is idempotent, and everything not fixed says why.
"""

import difflib
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.analysis.engine import analyze
from app.api.routes.scan import config_redactor, get_scan_store, redact_config_text
from app.main import app
from app.models.normalized import Vendor
from app.models.results import DECISIVE_ASSURANCE, Assurance, Status
from app.parsers.detector import STATUS_CONFIRMED, STATUS_UNVERIFIED, identify_vendor
from app.remediation import engine
from app.remediation.engine import RemediationStatus as S, analyze_text, parse_inputs, remediate_all, remediate_control
from app.remediation.recipes import RECIPES, Recipe

TESTS = Path(__file__).parent
FIXTURES = TESTS / "fixtures"
SAMPLES = TESTS.parent.parent / "sample"

RAW_INPUTS = {"syslog_server": "10.20.0.5", "ntp_server": "10.20.0.6", "ntp_key_id": "7",
              "ntp_key": "NtpKey2026x", "management_subnet": "10.10.0.0/24"}
INPUTS, _ = parse_inputs(RAW_INPUTS)
NOT_FIXED = {S.MANUAL_REVIEW, S.NEEDS_INPUT, S.NO_RECIPE}

CONFIRMED_SAMPLES = sorted(
    p for p in [*SAMPLES.glob("cisco/**/*.cfg"), *SAMPLES.glob("frontinet/*.cfg"), *FIXTURES.glob("*.cfg")]
    if identify_vendor(p.read_text()).confirmed
)


def _changed_lines(before: str, after: str) -> set[int]:
    """1-based numbers of original lines that were replaced or deleted."""
    changed = set()
    matcher = difflib.SequenceMatcher(a=before.splitlines(), b=after.splitlines(), autojunk=False)
    for tag, i1, i2, _, _ in matcher.get_opcodes():
        if tag in ("replace", "delete"):
            changed.update(range(i1 + 1, i2 + 1))
    return changed


def _statuses(plan) -> dict[str, S]:
    return {o.control_id: o.status for o in plan.outcomes}


def _scan(client, name: str, data: bytes) -> dict:
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        response = client.post("/api/scan", files=[("files", (name, data, "text/plain"))])
    assert response.status_code == 200, response.text
    return response.json()


# ── Cisco ────────────────────────────────────────────────────────────────────

def test_cisco_vulnerable_plan_fixes_what_is_safe_and_explains_the_rest():
    plan = remediate_all((FIXTURES / "cisco_vulnerable.cfg").read_text(), INPUTS)

    assert _statuses(plan) == {
        "MGMT-001": S.FIXED, "MGMT-002": S.FIXED, "MGMT-003": S.FIXED, "MGMT-004": S.FIXED,
        "MGMT-005": S.MANUAL_REVIEW,  # weak stored passwords need a new secret, not an invented hash
        "MGMT-006": S.FIXED, "MGMT-007": S.FIXED,
        "MGMT-008": S.MANUAL_REVIEW,  # no local account with a strong secret: AAA could lock admins out
        "MGMT-009": S.FIXED,
        "BOUNDARY-001": S.MANUAL_REVIEW,  # any-any ACL needs operator intent
        "BOUNDARY-002": S.FIXED, "BOUNDARY-003": S.FIXED, "LOG-001": S.FIXED, "LOG-002": S.FIXED,
        "CRYPTO-001": S.FIXED,
        "MGMT-011": S.NOT_FAILING,  # the MGMT-004 fix already removed every community, earlier in the plan
        "AUTH-001": S.FIXED, "AUTH-002": S.FIXED, "BOUNDARY-004": S.FIXED,
        "AUTH-003": S.MANUAL_REVIEW,  # a named account needs new credentials
    }
    assert all(c.passed for c in plan.checks)
    fixed = analyze_text(plan.fixed_config)
    for control_id in plan.fixed_controls:
        # decisive: parser evidence, or a documented default (no SNMP community left)
        assert all(r.status == Status.PASS and r.assurance in DECISIVE_ASSURANCE for r in fixed.control(control_id))
    text = plan.fixed_config
    assert "transport input ssh" in text and "transport input telnet" not in text
    assert "logging host 10.20.0.5" in text and "ntp server 10.0.0.1 key 7" in text
    # the community strings are secrets: the replacement comment never repeats them
    assert "public" not in text and "private" not in text


def test_cisco_single_control_carries_control_scope_evidence_and_before_after():
    text = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    outcome, after = remediate_control(text, "MGMT-006", {})

    assert outcome.status == S.FIXED and after is not None
    assert outcome.vendor == "cisco_ios" and outcome.hostname == "CORP-RTR-01"
    assert set(outcome.scopes) == {"line vty 0 4", "line con 0"}
    assert (85, " exec-timeout 0 0") in outcome.evidence
    assert outcome.control_status_before == "fail" and outcome.control_status_after == "pass"
    assert "- exec-timeout 0 0" in outcome.diff and "+ exec-timeout 5 0" in outcome.diff
    assert {c.name for c in outcome.checks} == {"vendor", "parse_coverage", "target", "no_regression"}
    assert outcome.fixed_config.count("exec-timeout 5 0") == 3
    assert outcome.before["posture"] < outcome.after["posture"]


# ── FortiGate ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [FIXTURES / "fortinet_vulnerable.cfg", SAMPLES / "frontinet" / "04_fortigate_vulnerable.cfg",
                                  SAMPLES / "frontinet" / "fortinet_demo_vulnerable.cfg"], ids=lambda p: p.name)
def test_fortigate_plan_output_verifies_as_fortios(path):
    """The SNMP remover used to comment `config hosts` / `next` but leave the nested `edit 1` / `end`
    live, closing `config system snmp community` early: the fixed file rescanned as vendor unverified."""
    plan = remediate_all(path.read_text(), INPUTS)

    ident = identify_vendor(plan.fixed_config)
    assert ident.status == STATUS_CONFIRMED, ident.reason
    assert ident.coverage.longest_foreign_run == 0 and ident.coverage.uncovered_count == 0
    remaining = {f.rule_id for f in analyze(ident.config).findings}
    # NOT_FAILING: an earlier fix in the plan already resolved it (MGMT-003 clears the WAN port MGMT-010 reads,
    # MGMT-004 removes the communities MGMT-011 reads)
    unresolved = {c for c, s in _statuses(plan).items() if s not in (S.FIXED, S.NOT_FAILING)}
    assert remaining == unresolved == {"BOUNDARY-001", "AUTH-003"}


def test_fortigate_snmp_default_community_block_commented_as_a_whole():
    plan = remediate_all((SAMPLES / "frontinet" / "04_fortigate_vulnerable.cfg").read_text(), {})
    lines = plan.fixed_config.splitlines()
    start = lines.index("config system snmp community")
    body = lines[start + 1:lines.index("end", start)]
    assert body and all(line.startswith("#") for line in body), body
    assert any("set query-v1-status" in line for line in body)
    assert "MGMT-004" in plan.fixed_controls


def test_broken_snmp_remediation_output_stays_unverified():
    """The previously downloaded broken output is genuinely malformed FortiOS; verification must keep rejecting it."""
    text = (FIXTURES / "fortigate_broken_snmp_remediation.cfg").read_text()
    ident = identify_vendor(text)
    assert ident.status == STATUS_UNVERIFIED
    assert ident.coverage.longest_foreign_run == 11
    assert remediate_control(text, "MGMT-004", {})[0].status == S.VENDOR_UNVERIFIED


def test_fortigate_multi_wan_allowaccess_and_crypto():
    config = """config system global
    set hostname "FW-01"
end
config system interface
    edit "wan1"
        set allowaccess ping https ssh http telnet
        set role wan
    next
    edit "wan2"
        set allowaccess https ssh
        set role wan
    next
    edit "lan"
        set allowaccess ping https ssh
        set role lan
    next
end
config vpn ipsec phase1-interface
    edit "vpn1"
        set proposal 3des-md5 aes256-sha256
        set dhgrp 2 14
    next
end
config firewall policy
    edit 1
        set srcaddr "lan"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
end
"""
    plan = remediate_all(config, {})
    text = plan.fixed_config
    assert {"MGMT-001", "MGMT-002", "MGMT-003", "CRYPTO-001"} <= set(plan.fixed_controls)
    assert '        set allowaccess ping\n        set role wan' in text
    assert '    edit "wan2"\n        unset allowaccess' in text
    assert "set allowaccess ping https ssh\n        set role lan" in text  # internal interface untouched
    assert "        set proposal aes256-sha256\n        set dhgrp 14\n" in text
    assert identify_vendor(text).coverage.uncovered_count == 0


# ── missing settings and nesting ─────────────────────────────────────────────

def test_missing_settings_are_added_inside_their_blocks():
    cisco = "hostname R1\n!\nline vty 0 4\n login local\n transport input ssh\n!\nend\n"
    outcome, _ = remediate_control(cisco, "MGMT-006", {})
    assert outcome.status == S.FIXED
    assert outcome.fixed_config == "hostname R1\n!\nline vty 0 4\n login local\n transport input ssh\n exec-timeout 5 0\n!\nend\n"

    outcome, _ = remediate_control(cisco, "LOG-001", INPUTS)
    assert outcome.status == S.FIXED
    assert outcome.fixed_config.endswith("!\nlogging host 10.20.0.5\nend\n")

    silent_banner = "\n".join(l for l in (FIXTURES / "fortinet_vulnerable.cfg").read_text().splitlines()
                              if "pre-login-banner" not in l)
    outcome, _ = remediate_control(silent_banner, "MGMT-009", {})
    assert outcome.status == S.FIXED  # FortiOS default is disabled (DEFAULT assurance): the setting is added
    assert "    set gui-theme mariner\n    set pre-login-banner enable\nend" in outcome.fixed_config


def test_fortigate_ntp_block_absent_is_created_nested_and_balanced():
    config = (FIXTURES / "fortinet_vulnerable.cfg").read_text()
    config = re.sub(r"config system ntp\n.*?\nend\n", "", config, flags=re.S)
    outcome, _ = remediate_control(config, "LOG-002", INPUTS)

    assert outcome.status == S.FIXED, outcome.reason
    assert ("config system ntp\n    set ntpsync enable\n    set type custom\n    set authentication enable\n"
            "    config ntpserver\n        edit 1\n            set server \"10.20.0.6\"\n"
            "            set authentication enable\n            set key-id 7\n            set key NtpKey2026x\n"
            "        next\n    end\nend") in outcome.fixed_config
    assert identify_vendor(outcome.fixed_config).coverage.longest_foreign_run == 0


def test_fortigate_ntp_server_added_to_existing_nested_block():
    config = """config system ntp
    set ntpsync enable
    config ntpserver
    end
end
config firewall policy
end
"""
    outcome, _ = remediate_control(config, "LOG-002", INPUTS)
    assert outcome.status == S.FIXED, outcome.reason
    assert "    config ntpserver\n        edit 1\n            set server \"10.20.0.6\"" in outcome.fixed_config
    assert outcome.fixed_config.index("        next\n    end\n    set authentication enable") > 0


def test_cisco_ntp_existing_server_gets_key_without_duplicating_it():
    config = "version 15.2\nhostname R1\n!\nntp server 10.0.0.1\nntp server 10.0.0.2 prefer\n!\nend\n"
    outcome, _ = remediate_control(config, "LOG-002", {"ntp_key_id": 3, "ntp_key": "SharedKey123"})
    assert outcome.status == S.FIXED, outcome.reason
    assert "ntp server 10.0.0.1 key 3\nntp server 10.0.0.2 prefer key 3" in outcome.fixed_config
    assert outcome.fixed_config.count("ntp server") == 2


# ── already fixed, idempotence, unrelated configuration ──────────────────────

@pytest.mark.parametrize("name", ["cisco_secure.cfg", "fortinet_secure.cfg"])
def test_already_fixed_configuration_is_left_alone(name):
    text = (FIXTURES / name).read_text()
    plan = remediate_all(text, INPUTS)
    assert plan.fixed_config is None and not plan.fixed_controls
    outcome, _ = remediate_control(text, "MGMT-001", INPUTS)
    assert outcome.status == S.NOT_FAILING and outcome.fixed_config is None and outcome.diff == ""


@pytest.mark.parametrize("path", CONFIRMED_SAMPLES, ids=lambda p: p.name)
def test_every_confirmed_sample_remediates_verified_and_idempotent(path):
    text = path.read_text()
    plan = remediate_all(text, INPUTS)
    if plan.fixed_config is None:
        assert all(o.status in NOT_FIXED | {S.NOT_FAILING} for o in plan.outcomes)
        return

    assert all(c.passed for c in plan.checks), plan.checks
    assert not any(o.status == S.VERIFICATION_FAILED for o in plan.outcomes)
    rescan = analyze_text(plan.fixed_config)
    assert rescan.confirmed and rescan.vendor == analyze_text(text).vendor
    for control_id in plan.fixed_controls:
        assert all(r.status == Status.PASS for r in rescan.control(control_id)), control_id
    # every control still failing says why it was not fixed
    still_failing = {r.control_id for r in rescan.results if r.status == Status.FAIL}
    assert all(_statuses(plan).get(c) in NOT_FIXED for c in still_failing), (still_failing, _statuses(plan))
    assert rescan.summary()["posture"] >= plan.before["posture"]

    again = remediate_all(plan.fixed_config, INPUTS)
    assert again.fixed_config is None and not again.fixed_controls
    # no placeholder or invented value ever reaches a generated configuration
    for token in ("$9$", "10.0.0.100", "10.0.0.50", "{", "Internal_Subnet", "Allowed_Servers", "REMEDIATED_HASH"):
        assert text.count(token) == plan.fixed_config.count(token), token


def test_single_control_remediation_is_idempotent():
    text = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    for control_id in ("MGMT-001", "MGMT-004", "CRYPTO-001", "LOG-002"):
        first, _ = remediate_control(text, control_id, INPUTS)
        assert first.status == S.FIXED
        second, _ = remediate_control(first.fixed_config, control_id, INPUTS)
        assert second.status == S.NOT_FAILING and second.fixed_config is None


def test_cisco_remediation_changes_only_the_failing_settings():
    config = """!
! core router -do not remove this comment
hostname EDGE
!
interface GigabitEthernet0/1
 description LAN
 ip address 192.168.1.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 192.0.2.1
banner motd ^
transport input telnet appears in this banner text
^
line con 0
 exec-timeout 5 0
line vty 0 4
 login local
 transport input telnet
 exec-timeout 5 0
line vty 5 15
 transport input ssh
 exec-timeout 5 0
!
end
"""
    outcome, _ = remediate_control(config, "MGMT-001", {})
    assert outcome.status == S.FIXED
    assert _changed_lines(config, outcome.fixed_config) == {17}
    assert outcome.fixed_config.replace(" transport input ssh\n exec-timeout 5 0\nline vty 5",
                                        " transport input telnet\n exec-timeout 5 0\nline vty 5") == config


def test_fortigate_remediation_changes_only_the_failing_settings():
    config = (FIXTURES / "fortinet_vulnerable.cfg").read_text()
    outcome, _ = remediate_control(config, "MGMT-006", {})
    assert outcome.status == S.FIXED
    assert _changed_lines(config, outcome.fixed_config) == {7}
    assert outcome.fixed_config.splitlines()[6] == "    set admintimeout 5"
    # config-version comments and every other block survive byte for byte
    assert outcome.fixed_config.replace("admintimeout 5", "admintimeout 480") == config


def test_crlf_and_trailing_newline_are_preserved():
    config = "version 15.2\r\nhostname R1\r\n!\r\nip ssh version 1\r\n!\r\nend\r\n"
    outcome, _ = remediate_control(config, "MGMT-007", {})
    assert outcome.status == S.FIXED, outcome.reason
    assert outcome.fixed_config == "version 15.2\r\nhostname R1\r\n!\r\nip ssh version 2\r\n!\r\nend\r\n"


# ── honest non-fixes ─────────────────────────────────────────────────────────

def test_missing_input_is_needs_input_never_fixed():
    text = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    outcome, after = remediate_control(text, "LOG-001", {})
    assert outcome.status == S.NEEDS_INPUT and after is None
    assert outcome.missing_inputs == ["syslog_server"] and outcome.inputs == ["syslog_server"]
    assert outcome.fixed_config is None and outcome.diff == "" and outcome.checks == []

    outcome, _ = remediate_control(text, "LOG-002", {"ntp_key_id": 1})
    assert outcome.status == S.NEEDS_INPUT and outcome.missing_inputs == ["ntp_key"]


@pytest.mark.parametrize("raw, field", [
    ({"syslog_server": "10.0.0.1\nip http server"}, "syslog_server"),
    ({"syslog_server": "not-an-ip"}, "syslog_server"),
    ({"management_subnet": "0.0.0.0/0"}, "management_subnet"),
    ({"ntp_key": "has space inside"}, "ntp_key"),
    ({"ntp_key": 'quote"injection'}, "ntp_key"),
    ({"ntp_key_id": "0"}, "ntp_key_id"),
    ({"commands": "no aaa new-model"}, "commands"),
])
def test_invalid_inputs_are_rejected(raw, field):
    values, errors = parse_inputs(raw)
    assert field in errors and field not in values


def test_invalid_generated_output_is_kept_for_review_and_never_fixed(monkeypatch):
    text = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    foreign = ["set system host-name EDGE", "set system services telnet", "set interfaces ge-0/0/0 unit 0",
               "set protocols lldp interface all", "set snmp community public", "set system syslog host 1.1.1.1"]

    def broken(ctx):
        return [*ctx.lines[:-1], *foreign, ctx.lines[-1]]

    monkeypatch.setitem(RECIPES, ("MGMT-007", Vendor.CISCO_IOS), Recipe(broken, "broken recipe"))
    outcome, after = remediate_control(text, "MGMT-007", {})

    assert outcome.status == S.VERIFICATION_FAILED and after is None
    assert "set system services telnet" in outcome.fixed_config  # preserved for review
    failed = {c.name: c.detail for c in outcome.checks if not c.passed}
    assert "vendor" in failed and "no longer confirmed" in failed["vendor"]
    assert outcome.reason.startswith("Verification failed:")

    plan = remediate_all(text, INPUTS)  # the broken step is skipped, later steps still verify
    monkeypatch.undo()
    assert _statuses(plan)["MGMT-007"] == S.VERIFICATION_FAILED
    assert "set system services telnet" not in (plan.fixed_config or "")


def test_output_that_does_not_fix_the_control_or_regresses_another_fails_verification(monkeypatch):
    text = (FIXTURES / "cisco_vulnerable.cfg").read_text()

    def no_fix(ctx):
        return [l.replace("hostname CORP-RTR-01", "hostname CORP-RTR-02") for l in ctx.lines]

    def regress(ctx):  # fixes SSH but turns a passing control (idle timeout on a secure config) into a FAIL
        return [l.replace("ip ssh version 1", "ip ssh version 2").replace("exec-timeout 5 0", "exec-timeout 0 0")
                for l in ctx.lines]

    monkeypatch.setitem(RECIPES, ("MGMT-007", Vendor.CISCO_IOS), Recipe(no_fix, "no fix"))
    outcome, _ = remediate_control(text, "MGMT-007", {})
    assert outcome.status == S.VERIFICATION_FAILED
    assert not next(c for c in outcome.checks if c.name == "target").passed

    secure = (FIXTURES / "cisco_secure.cfg").read_text().replace("ip ssh version 2", "ip ssh version 1")
    monkeypatch.setitem(RECIPES, ("MGMT-007", Vendor.CISCO_IOS), Recipe(regress, "regress"))
    outcome, _ = remediate_control(secure, "MGMT-007", {})
    assert outcome.status == S.VERIFICATION_FAILED
    regression = next(c for c in outcome.checks if c.name == "no_regression")
    assert not regression.passed and "MGMT-006 pass → fail" in regression.detail


@pytest.mark.parametrize("path", [SAMPLES / "unknown.cfg", SAMPLES / "paloalto.cfg",
                                  FIXTURES / "lookalikes" / "arista_eos.cfg", FIXTURES / "lookalikes" / "cisco_asa.cfg",
                                  FIXTURES / "lookalikes" / "mixed_ios_foreign_block.cfg"], ids=lambda p: p.name)
def test_unknown_and_unverified_vendors_are_blocked(path):
    text = path.read_text()
    plan = remediate_all(text, INPUTS)
    assert plan.vendor_status != STATUS_CONFIRMED and plan.fixed_config is None and not plan.outcomes
    for control_id in ("MGMT-001", "LOG-001"):
        outcome, _ = remediate_control(text, control_id, INPUTS)
        assert outcome.status == S.VENDOR_UNVERIFIED and outcome.fixed_config is None and outcome.diff == ""


def test_heuristic_verdict_cannot_trigger_remediation(monkeypatch):
    """A FAIL whose weakest evidence is provisional is never remediated, even on a confirmed vendor."""
    text = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    real = engine.analyze_text

    def provisional(t):
        analysis = real(t)
        for r in analysis.results:
            if r.control_id == "MGMT-007" and r.status == Status.FAIL:
                r.assurance = Assurance.HEURISTIC
        return analysis

    monkeypatch.setattr(engine, "analyze_text", provisional)
    outcome, _ = remediate_control(text, "MGMT-007", {})
    assert outcome.status == S.PROVISIONAL and outcome.fixed_config is None


# ── API ──────────────────────────────────────────────────────────────────────

def test_api_remediation_then_real_rescan_matches_the_plan():
    client = TestClient(app)
    raw = (FIXTURES / "cisco_vulnerable.cfg").read_bytes()
    scan = _scan(client, "cisco.cfg", raw)

    plan = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"], "inputs": RAW_INPUTS})
    assert plan.status_code == 200, plan.text
    device = plan.json()["devices"][0]
    assert device["before"]["posture"] == scan["posture"] and device["before"]["coverage"] == scan["coverage"]
    statuses = {r["rule_id"]: r["status"] for r in device["remediations"]}
    # not_failing: an earlier fix in the plan already resolved it (MGMT-004 removes the communities MGMT-011 reads)
    assert {c for c, s in statuses.items() if s not in ("fixed", "not_failing")} == {
        "MGMT-005", "MGMT-008", "BOUNDARY-001", "AUTH-003"}
    assert all(c["passed"] for c in device["checks"])

    download = client.post("/api/download-fixed", json={"scan_id": scan["scan_id"], "inputs": RAW_INPUTS})
    assert download.status_code == 200
    # the plan shows the verified configuration with secrets redacted; the download is that same file, unredacted
    redactor = config_redactor(get_scan_store()[scan["scan_id"]]["configs"])
    redactor.add_secret(RAW_INPUTS["ntp_key"])
    assert redact_config_text(redactor, download.text) == device["fixed_config"]
    assert "0822455D0A16" in download.text and RAW_INPUTS["ntp_key"] in download.text
    assert "0822455D0A16" not in device["fixed_config"] and RAW_INPUTS["ntp_key"] not in device["fixed_config"]

    rescan = _scan(client, "cisco_fixed.cfg", download.content)
    assert rescan["vendor_identification"][0]["status"] == "confirmed"
    assert rescan["posture"] == device["after"]["posture"] > scan["posture"]
    assert rescan["coverage"] == device["after"]["coverage"]
    assert rescan["critical_unassessed"] == device["after"]["critical_unassessed"]
    assert {f["rule_id"] for f in rescan["findings"]} == {"MGMT-005", "MGMT-008", "BOUNDARY-001", "AUTH-003"}
    passed = {r["control_id"] for r in rescan["results"] if r["status"] == "pass"}
    assert set(device["fixed_controls"]) <= passed


def test_api_fortigate_download_rescans_as_confirmed_fortinet():
    client = TestClient(app)
    scan = _scan(client, "fgt.cfg", (SAMPLES / "frontinet" / "04_fortigate_vulnerable.cfg").read_bytes())
    fixed = client.post("/api/download-fixed", json={"scan_id": scan["scan_id"]})
    assert fixed.status_code == 200
    rescan = _scan(client, "fgt_fixed.cfg", fixed.content)

    assert rescan["vendor_identification"][0]["status"] == "confirmed"
    assert rescan["devices"][0]["vendor"] == "fortinet"
    # without operator inputs, syslog and NTP stay failing; the any-any policy needs a human
    assert {f["rule_id"] for f in rescan["findings"]} == {"BOUNDARY-001", "LOG-001", "LOG-002", "AUTH-003"}
    assert rescan["posture"] > scan["posture"]
    assert not rescan["adaptive_configs"]


def test_api_remediate_single_finding_and_inputs():
    client = TestClient(app)
    scan = _scan(client, "cisco.cfg", (FIXTURES / "cisco_vulnerable.cfg").read_bytes())
    body = {"scan_id": scan["scan_id"], "rule_id": "LOG-001", "device_hostname": "CORP-RTR-01"}

    needs = client.post("/api/remediate", json=body).json()
    assert needs["status"] == "needs_input" and needs["fixed_config"] is None
    assert [i["name"] for i in needs["required_inputs"]] == ["syslog_server"]

    bad = client.post("/api/remediate", json={**body, "inputs": {"syslog_server": "10.0.0.1\nip http server"}})
    assert bad.status_code == 422

    fixed = client.post("/api/remediate", json={**body, "inputs": {"syslog_server": "10.20.0.5"},
                                               # extra fields are not command channels
                                               "remediation_commands": "ip http server"}).json()
    assert fixed["status"] == "fixed" and "+logging host 10.20.0.5" in fixed["diff"]
    assert fixed["before"]["posture"] < fixed["after"]["posture"]
    assert fixed["evidence"]["line_numbers"] and fixed["control_status_after"] == "pass"
    assert not any(line.strip() == "ip http server" for line in fixed["fixed_config"].splitlines()[66:])
    assert client.post("/api/verify", json={"scan_id": scan["scan_id"], "remediation_commands": "x"}).status_code in (404, 405)


def test_api_unknown_vendor_is_blocked_and_heuristic_findings_listed_as_unverified():
    client = TestClient(app)
    scan = _scan(client, "unknown.cfg", (SAMPLES / "unknown.cfg").read_bytes())
    assert any(f["rule_id"] == "MGMT-001" and f["assurance"] == "heuristic" for f in scan["findings"])

    remediate = client.post("/api/remediate", json={"scan_id": scan["scan_id"], "rule_id": "MGMT-001",
                                                    "device_hostname": scan["devices"][0]["hostname"],
                                                    "config_index": 0})
    assert remediate.status_code == 200 and remediate.json()["status"] == "vendor_unverified"
    assert remediate.json()["fixed_config"] is None and remediate.json()["diff"] == ""

    device = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    assert device["remediations"] and {r["status"] for r in device["remediations"]} == {"vendor_unverified"}
    assert device["fixed_config"] is None
    assert client.post("/api/download-fixed", json={"scan_id": scan["scan_id"]}).status_code == 409


def test_api_ai_proposal_in_stored_scan_blocks_remediation_on_a_confirmed_vendor():
    """An AI proposal (UNKNOWN + proposed FAIL) never triggers remediation, even where the parser could decide."""
    client = TestClient(app)
    scan = _scan(client, "cisco.cfg", (FIXTURES / "cisco_vulnerable.cfg").read_bytes())
    stored = get_scan_store()[scan["scan_id"]]
    for r in stored["result"].device_results[0]:
        if r.control_id == "MGMT-007":
            r.status, r.proposed_status, r.assurance, r.failure = Status.UNKNOWN, Status.FAIL, Assurance.AI_VERIFIED, None

    single = client.post("/api/remediate", json={"scan_id": scan["scan_id"], "rule_id": "MGMT-007",
                                                 "device_hostname": "CORP-RTR-01"}).json()
    assert single["status"] == "provisional" and single["fixed_config"] is None

    device = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    assert {r["rule_id"]: r["status"] for r in device["remediations"]}["MGMT-007"] == "provisional"
    assert "ip ssh version 1" in device["fixed_config"]
    download = client.post("/api/download-fixed", json={"scan_id": scan["scan_id"]})
    assert "ip ssh version 1" in download.text
