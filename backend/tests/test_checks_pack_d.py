"""BOUNDARY-004: routed interfaces that send ICMP redirects, answer proxy-ARP or forward directed broadcasts."""

from __future__ import annotations

import pathlib

import pytest

from app.models.results import Assurance, Status
from app.remediation.engine import RemediationStatus, analyze_generic_text, analyze_text, remediate_control

REPO = pathlib.Path(__file__).parents[2]
IOS = (REPO / "backend" / "tests" / "fixtures" / "demo" / "cisco_edge_vulnerable.cfg").read_text(encoding="utf-8")
FORTI = (REPO / "sample" / "frontinet" / "04_fortigate_vulnerable.cfg").read_text(encoding="utf-8")
HARDEN = " no ip redirects\n no ip proxy-arp"


def _by_scope(text):
    return {r.scope: (r.status, r.assurance) for r in analyze_text(text).control("BOUNDARY-004")}


def test_ios_defaults_leave_redirects_and_proxy_arp_on(seeded_adaptive_db):
    results = _by_scope(IOS)
    assert results == {"interface GigabitEthernet0/0/0": (Status.FAIL, Assurance.DEFAULT),
                       "interface GigabitEthernet0/0/1": (Status.FAIL, Assurance.DEFAULT)}


def test_a_hardened_interface_passes_and_the_other_still_fails(seeded_adaptive_db):
    text = IOS.replace(" description LAN-USERS", f" description LAN-USERS\n{HARDEN}", 1)
    assert {s for s, _ in _by_scope(text).values()} == {Status.FAIL}
    assert list(_by_scope(text)) == ["interface GigabitEthernet0/0/0"]
    both = text.replace(" description WAN-UPLINK-TO-ISP", f" description WAN-UPLINK-TO-ISP\n{HARDEN}", 1)
    assert {r.status for r in analyze_text(both).control("BOUNDARY-004")} == {Status.PASS}


def test_an_explicit_directed_broadcast_fails_on_parser_evidence(seeded_adaptive_db):
    text = IOS.replace(" description LAN-USERS", f" description LAN-USERS\n{HARDEN}\n ip directed-broadcast", 1)
    assert _by_scope(text)["interface GigabitEthernet0/0/1"] == (Status.FAIL, Assurance.PARSER)


def test_the_fix_hardens_every_failing_interface(seeded_adaptive_db):
    outcome, _ = remediate_control(IOS, "BOUNDARY-004", {})
    assert outcome.status == RemediationStatus.FIXED, outcome.reason
    assert outcome.fixed_config.count("no ip proxy-arp") == 2


def test_fortigate_has_no_such_interface_services(seeded_adaptive_db):
    assert {r.status for r in analyze_text(FORTI).control("BOUNDARY-004")} == {Status.N_A}


@pytest.mark.parametrize("child, expected", [
    ("ip proxy-arp", Status.FAIL),
    ("ip directed-broadcast", Status.FAIL),
])
def test_other_dialects_state_it_explicitly(seeded_adaptive_db, child, expected):
    result = analyze_generic_text(f"interface Ethernet1\n   {child}\n")
    assert {(r.status, r.assurance) for r in result.control("BOUNDARY-004")} == {(expected, Assurance.CONFIRMED)}


def test_one_interface_switching_a_service_off_decides_nothing(seeded_adaptive_db):
    """Off on Ethernet1 says nothing of the other interfaces, which keep the platform default: undecided."""
    result = analyze_generic_text("interface Ethernet1\n   no ip redirects\n")
    assert {r.status for r in result.control("BOUNDARY-004")} == {Status.UNKNOWN}
