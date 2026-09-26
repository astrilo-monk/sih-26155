"""Absence read from learned knowledge: a setting no device ships with, that an understood dialect would state
and nothing states, is not configured -a decided FAIL, never a guess about syntax nobody taught."""

import pathlib

from app.controls.evaluate import evaluate_controls
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Status

TEACH = pathlib.Path(__file__).parents[2] / "teach"
PAN = """set deviceconfig system hostname FW-01
set deviceconfig system login-banner "Authorized access only"
set deviceconfig system service disable-telnet yes
set deviceconfig system syslog-server 10.0.0.5
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.0.0.6
"""


def _only(text, control_id):
    """One control's result for a configuration no parser reads."""
    config = NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="t"),
                              raw_config=text, raw_lines=text.splitlines())
    [one] = [r for r in evaluate_controls(config) if r.control_id == control_id]
    return one


def test_an_understood_dialect_without_the_setting_fails_and_says_how_it_would_be_written(seeded_adaptive_db):
    junos = (TEACH / "juniper_junos_5_configs" / "juniper_01_secure.conf").read_text(encoding="utf-8")
    aaa = _only(junos, "MGMT-008")
    assert aaa.status == Status.FAIL and aaa.assurance == Assurance.CONFIRMED and not aaa.evidence.line_numbers
    assert "Juniper Junos states it as 'authentication-order [ … password ]'" in aaa.reason
    # nobody taught how Junos writes NTP authentication: its absence is not evidence
    assert _only(junos, "LOG-002").status == Status.UNKNOWN


def test_a_line_naming_the_setting_in_untaught_syntax_keeps_absence_silent(seeded_adaptive_db):
    assert _only(PAN, "MGMT-008").status == Status.FAIL
    variant = PAN + "set config shared server-profile tacplus CORP-TACACS timeout 5\n"
    assert _only(variant, "MGMT-008").status == Status.NOT_CONFIGURED


def test_a_fragment_is_not_understood(seeded_adaptive_db):
    fragment = "set deviceconfig system syslog-server 10.0.0.5\nset deviceconfig system hostname FW-01\n"
    assert _only(fragment, "MGMT-008").status == Status.NOT_CONFIGURED


def test_without_learned_knowledge_absence_says_nothing():
    assert _only(PAN, "MGMT-008").status == Status.NOT_CONFIGURED


def test_a_missing_setting_is_added_in_the_dialects_own_syntax_and_verified(seeded_adaptive_db):
    from app.remediation.engine import RemediationStatus
    from app.remediation.recipes import parse_inputs
    from app.remediation.writeback import writeback_control

    pan = (pathlib.Path(__file__).parents[2] / "demo-sih" / "paloalto_fw_vulnerable.cfg").read_text(encoding="utf-8")
    asked, _ = writeback_control(pan, "LOG-001", {})
    assert asked.status == RemediationStatus.NEEDS_INPUT and asked.missing_inputs == ["syslog_server"]
    inputs, _ = parse_inputs({"syslog_server": "10.20.0.5", "banner_text": "Authorized access only.  Activity is monitored."})
    for control_id, line in (("LOG-001", "+set deviceconfig system syslog-server 10.20.0.5"),
                             ("MGMT-009", '+set deviceconfig system login-banner "Authorized access only. Activity is monitored."')):
        outcome, after = writeback_control(pan, control_id, inputs)
        assert outcome.status == RemediationStatus.FIXED and after is not None
        assert line in outcome.diff.splitlines()

    # a brace-structured file: a line appended at the end would sit outside its block, so nothing is written
    junos = (TEACH / "juniper_junos_5_configs" / "juniper_02_insecure.conf").read_text(encoding="utf-8")
    assert _only(junos, "LOG-001").status == Status.FAIL
    assert writeback_control(junos, "LOG-001", inputs)[0].status == RemediationStatus.NO_RECIPE


def test_a_banner_that_could_break_the_line_is_refused():
    from app.remediation.recipes import parse_inputs

    for bad in ('Keep out"; delete', "short", "line one\nline two ! comment {"):
        assert "banner_text" in parse_inputs({"banner_text": bad})[1]
