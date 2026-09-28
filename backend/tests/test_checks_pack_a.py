"""MGMT-010 (management reachable from an untrusted interface) and MGMT-011 (SNMPv1/v2c in use)."""

from __future__ import annotations

import pathlib

import pytest

from app.controls.catalog import CONTROLS
from app.facts.heuristics import heuristic_facts
from app.facts.predicates import MGMT_EXPOSED
from app.models.results import Assurance, Status
from app.remediation.engine import RemediationStatus, analyze_generic_text, analyze_text, remediate_control

FORTI = """config system global
    set hostname "FW-A"
end
config system interface
    edit "wan1"
        set ip 198.51.100.2 255.255.255.252
        set allowaccess {wan}
        set role wan
    next
    edit "internal"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping https ssh
        set role lan
    next
end
config firewall policy
    edit 1
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
end
"""

PANOS = """set deviceconfig system hostname PA-A
set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2
set network interface ethernet ethernet1/1 layer3 interface-management-profile OUTSIDE
set network interface ethernet ethernet1/2 layer3 interface-management-profile INSIDE
set network profiles interface-management-profile OUTSIDE {service}
set network profiles interface-management-profile INSIDE ssh yes
"""


# a full IOS configuration the detector confirms, without its SNMP lines
IOS = "\n".join(line for line in (pathlib.Path(__file__).parents[2] / "backend" / "tests" / "fixtures" / "demo" / "cisco_edge_vulnerable.cfg")
                 .read_text(encoding="utf-8").splitlines() if not line.startswith("snmp-server")) + "\n"


def _statuses(analysis, control_id):
    return {(r.status, r.assurance) for r in analysis.control(control_id)}


# ── MGMT-010 ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("wan, expected", [
    ("https ssh", Status.FAIL),
    ("snmp", Status.FAIL),
    ("fgfm", Status.FAIL),
    ("ping", Status.PASS),          # a diagnostic, not a way to manage the device
])
def test_fortigate_management_on_a_wan_interface(seeded_adaptive_db, wan, expected):
    result = analyze_text(FORTI.replace("{wan}", wan))
    assert {r.status for r in result.control("MGMT-010")} == {expected}


def test_fortigate_fix_removes_every_management_service_from_the_wan_port(seeded_adaptive_db):
    outcome, after = remediate_control(FORTI.replace("{wan}", "ping https ssh snmp"), "MGMT-010", {})
    assert outcome.status == RemediationStatus.FIXED, outcome.reason
    assert "set allowaccess ping" in outcome.fixed_config
    # the LAN interface keeps its management access
    assert "set allowaccess ping https ssh\n" in outcome.fixed_config


def test_ios_binds_no_management_service_to_an_interface(seeded_adaptive_db):
    result = analyze_text(IOS)
    assert {r.status for r in result.control("MGMT-010")} == {Status.N_A}


@pytest.mark.parametrize("service, expected", [
    ("https yes", (Status.FAIL, Assurance.HEURISTIC)),
    ("telnet yes", (Status.FAIL, Assurance.HEURISTIC)),
    ("ping yes", None),             # not a management service
    ("https no", None),
])
def test_a_management_profile_bound_to_an_external_zone_is_joined_across_lines(seeded_adaptive_db, service, expected):
    facts = [f for f in heuristic_facts(PANOS.replace("{service}", service).splitlines()) if f.predicate == MGMT_EXPOSED]
    assert [f.scope for f in facts] == (["interface ethernet1/1"] if expected else [])
    if expected:
        assert _statuses(analyze_generic_text(PANOS.replace("{service}", service)), "MGMT-010") == {expected}


def test_a_zone_is_external_only_when_its_name_says_so(seeded_adaptive_db):
    text = PANOS.replace("{service}", "https yes").replace("zone untrust", "zone dmz")
    assert not [f for f in heuristic_facts(text.splitlines()) if f.predicate == MGMT_EXPOSED]


@pytest.mark.parametrize("line, expected", [
    ("set security zones security-zone untrust host-inbound-traffic system-services ssh", True),
    ("set security zones security-zone untrust interfaces ge-0/0/0.0 host-inbound-traffic system-services all", True),
    ("set security zones security-zone trust host-inbound-traffic system-services all", None),
])
def test_junos_host_inbound_services_on_an_untrust_zone(seeded_adaptive_db, line, expected):
    result = analyze_generic_text(f"set system host-name J1\n{line}\n")
    statuses = {r.status for r in result.control("MGMT-010")}
    assert statuses == ({Status.FAIL} if expected else {Status.NOT_CONFIGURED})


# ── MGMT-011 ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("snmp, expected", [
    ("snmp-server community N0c-7f3k RO SNMP-ACL\n", Status.FAIL),     # a strong string is still v2c
    ("snmp-server group NOC v3 priv\n", Status.PASS),
    ("", Status.PASS),
])
def test_ios_community_based_snmp(seeded_adaptive_db, snmp, expected):
    result = analyze_text(IOS.replace("logging host", f"{snmp}logging host", 1))
    assert {r.status for r in result.control("MGMT-011")} == {expected}


def test_a_community_read_by_a_seed_means_v2c(seeded_adaptive_db):
    result = analyze_generic_text("set snmp community N0c-7f3k authorization read-only\n")
    assert _statuses(result, "MGMT-011") == {(Status.FAIL, Assurance.CONFIRMED)}
    # and it is the same community MGMT-004 passes: strong string, read-only
    assert {r.status for r in result.control("MGMT-004")} == {Status.PASS}


def test_the_catalog_maps_the_new_checks_only_to_verified_items():
    assert {m.requirement_id for m in CONTROLS["MGMT-010"].mappings if m.framework == "CIS"} == {"1.3"}
    assert {m.requirement_id for m in CONTROLS["MGMT-011"].mappings if m.framework == "CIS"} == {"2.3.1"}
