"""
Phase 1b -a vendor profile is confirmed only when the config follows its grammar.

The fingerprint detector matches shared tokens (``hostname``, ``!``,
``interface``, ``config``/``edit``/``set``). Look-alike dialects and mixed
files must come out UNVERIFIED and take the unknown-vendor path; real Cisco and
FortiGate configs must stay confirmed.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import app.config as app_config
from app.main import app
from app.models.normalized import Vendor
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.coverage import parse_coverage
from app.parsers.detector import (
    MAX_FOREIGN_RUN,
    MIN_UNCOVERED_LINES,
    STATUS_CONFIRMED,
    STATUS_UNKNOWN,
    STATUS_UNVERIFIED,
    detect_vendor,
    identify_vendor,
)
from app.parsers.fortinet import FortinetParser

REPO = Path(__file__).resolve().parents[2]
LOOKALIKES = Path(__file__).parent / "fixtures" / "lookalikes"
SNAPSHOT = json.loads((Path(__file__).parent / "snapshots" / "phase0_findings.json").read_text())

UNVERIFIED_LOOKALIKES = {
    "arista_eos.cfg": Vendor.CISCO_IOS,
    "cisco_nxos.cfg": Vendor.CISCO_IOS,
    "cisco_iosxr.cfg": Vendor.CISCO_IOS,
    "cisco_asa.cfg": Vendor.CISCO_IOS,
    "dell_os10.cfg": Vendor.CISCO_IOS,
    "brocade_icx.cfg": Vendor.CISCO_IOS,
    "mixed_ios_foreign_block.cfg": Vendor.CISCO_IOS,
    "fortiswitch.cfg": Vendor.FORTINET,
}


def _text(name: str) -> str:
    return (LOOKALIKES / name).read_text(encoding="utf-8")


def _ios_coverage(text: str):
    return parse_coverage(CiscoIOSParser().parse(text))


@pytest.mark.parametrize("name,fingerprint", UNVERIFIED_LOOKALIKES.items())
def test_lookalike_dialects_fingerprint_as_a_vendor_but_are_unverified(name, fingerprint):
    text = _text(name)
    assert detect_vendor(text) == fingerprint

    identification = identify_vendor(text)
    assert identification.status == STATUS_UNVERIFIED, identification.coverage
    assert identification.detected_vendor == fingerprint
    assert identification.vendor == Vendor.UNKNOWN
    assert identification.config is None
    assert identification.reason


def test_real_iosxe_config_with_exec_banner_and_xe_features_stays_confirmed():
    identification = identify_vendor(_text("cisco_iosxe_exec_banner.cfg"))
    assert identification.status == STATUS_CONFIRMED, identification.coverage
    assert identification.coverage.uncovered_count == 0


@pytest.mark.parametrize("entry", SNAPSHOT["entries"], ids=lambda e: e["file"])
def test_real_fixtures_stay_confirmed(entry):
    identification = identify_vendor((REPO / entry["file"]).read_text(encoding="utf-8"))
    assert identification.status == STATUS_CONFIRMED
    assert identification.vendor.value == entry["vendor"]


def test_unverified_config_takes_the_unknown_vendor_path_in_the_api():
    interpreter = MagicMock(return_value=[])
    with patch("app.api.routes.scan.interpret_lines", interpreter), \
         patch("app.api.routes.scan.is_available", return_value=False):
        resp = TestClient(app).post(
            "/api/scan", files=[("files", ("leaf1.cfg", _text("arista_eos.cfg").encode(), "text/plain"))],
        )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["devices"][0]["vendor"] == "unknown"
    [ident] = data["vendor_identification"]
    assert ident["status"] == "unverified" and ident["detected_vendor"] == "cisco_ios"
    assert ident["parse_coverage"] < 0.7 and ident["uncovered_lines"] >= MIN_UNCOVERED_LINES
    assert ident["reason"]
    assert not any(f["rule_id"].startswith("MGMT-") for f in data["findings"])
    assert any("resembles 'cisco_ios'" in r for r in data["adaptive"]["provisional_reasons"])


@pytest.mark.parametrize("fixture", ["cisco_vulnerable.cfg", "fortinet_vulnerable.cfg"])
def test_confirmed_scan_reports_its_coverage(fixture):
    text = (Path(__file__).parent / "fixtures" / fixture).read_bytes()
    data = TestClient(app).post("/api/scan", files=[("files", (fixture, text, "text/plain"))]).json()
    [ident] = data["vendor_identification"]
    assert ident["status"] == "confirmed" and ident["reason"] is None
    assert ident["parse_coverage"] >= 0.7


def test_unknown_config_is_reported_unknown():
    identification = identify_vendor((REPO / "sample" / "unknown.cfg").read_text())
    assert identification.status == STATUS_UNKNOWN
    assert identification.coverage is None


def test_a_few_foreign_lines_in_a_small_cisco_config_do_not_reject_it():
    text = "hostname R1\n!\ninterface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n!\nfoo bar\nbaz qux\n"
    identification = identify_vendor(text)
    assert identification.coverage.ratio < 0.7
    assert identification.coverage.uncovered_count < MIN_UNCOVERED_LINES
    assert identification.status == STATUS_CONFIRMED


def test_a_pasted_foreign_block_is_rejected_even_with_a_high_ratio():
    identification = identify_vendor(_text("mixed_ios_foreign_block.cfg"))
    assert identification.coverage.ratio >= 0.7
    assert identification.coverage.longest_foreign_run >= MAX_FOREIGN_RUN
    assert "consecutive" in identification.reason


def test_threshold_is_a_setting(monkeypatch):
    text = _text("arista_eos.cfg")
    monkeypatch.setattr(app_config.settings, "vendor_parse_coverage_threshold", 0.0)
    assert identify_vendor(text).status == STATUS_CONFIRMED
    assert identify_vendor(text, threshold=0.99).status == STATUS_UNVERIFIED


# ── grammar details ──────────────────────────────────────────────────────────

def test_negated_statements_are_validated_like_positive_ones():
    report = _ios_coverage("hostname R1\nno interface Ethernet1\nno interface Loopback0\nno username admin\n")
    assert report.uncovered_line_numbers == [2]


def test_interface_names_are_case_sensitive():
    report = _ios_coverage("hostname R1\ninterface gigabitethernet0/1\ninterface GigabitEthernet0/1\n")
    assert report.uncovered_line_numbers == [2]


def test_children_of_interface_and_line_blocks_are_validated():
    text = (
        "interface GigabitEthernet0/0\n"
        " ip address 10.0.0.1 255.255.255.0\n"
        " nameif outside\n"          # ASA
        " vrf member management\n"   # NX-OS
        " vrf forwarding Mgmt\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        " vty-pool default\n"
    )
    report = _ios_coverage(text)
    assert report.uncovered_line_numbers == [3, 4, 8]


def test_children_of_non_block_commands_are_foreign():
    report = _ios_coverage("username admin\n group root-lr\n secret 5 $1$x\nntp\n server 10.0.0.1\n")
    assert report.uncovered_line_numbers == [2, 3, 4, 5]


def test_every_banner_type_body_is_covered():
    text = "banner exec ^C\nWelcome\n  to the device\n^C\nbanner incoming #\nhello\n#\nbanner motd ^Cone line^C\n"
    report = _ios_coverage(text)
    assert report.uncovered_count == 0


def test_fortios_grammar_requires_balanced_blocks():
    text = (
        "config system global\n"
        "    set hostname FG1\n"
        "end\n"
        "set admintimeout 480\n"      # outside any config block
        "next\n"                       # no edit to close
        "edit 1\n"                     # edit outside config
        "system-name something\n"      # not FortiOS at all
        "config system interface\n"
        "    edit port1\n"
        '        set description "multi\n'
        'line"\n'
        "    next\n"
        "end\n"
    )
    report = parse_coverage(FortinetParser().parse(text))
    lines = text.splitlines()
    uncovered = {lines[n - 1].strip() for n in report.uncovered_line_numbers}
    assert uncovered == {"set admintimeout 480", "next", "edit 1", "system-name something"}
    assert report.covered_lines == 9
    assert report.profile_mismatch  # no FortiGate-only section


def test_fortios_grammar_without_a_fortigate_section_is_not_a_fortigate():
    identification = identify_vendor(_text("fortiswitch.cfg"))
    assert identification.coverage.ratio == 1.0
    assert "FortiGate" in identification.reason
