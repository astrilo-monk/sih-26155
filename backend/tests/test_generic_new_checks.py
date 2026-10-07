"""
MGMT-012, BOUNDARY-006 and CRYPTO-003 on the generic path: shipped seeds read SNMPv3 levels and the ASA's minimum TLS
version from their own lines, and an understood configuration that never names SNMPv3 or BGP / OSPF is N/A for
those checks. Any line naming the feature keeps it undecided; a configuration nobody understands is never N/A.
"""

from pathlib import Path

import pytest

from app.models.results import Assurance, Status
from app.remediation.engine import analyze_generic_text

REFERENCE = Path(__file__).parent / "fixtures" / "seed_coverage"


def _statuses(text: str, control_id: str) -> set:
    return {(r.status, r.assurance) for r in analyze_generic_text(text).control(control_id)}


def _status(text: str, control_id: str) -> set:
    return {r.status for r in analyze_generic_text(text).control(control_id)}


def _with(name: str, *lines: str) -> str:
    return (REFERENCE / name).read_text(encoding="utf-8").rstrip("\n") + "\n" + "\n".join(lines) + "\n"


# ── read from a line ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("name, line, expected", [
    ("arista.conf", "snmp-server group NETOPS v3 auth read all", Status.FAIL),
    ("arista.conf", "snmp-server group NETOPS v3 priv", Status.PASS),
    ("asa.conf", "snmp-server group NETOPS v3 noauth", Status.FAIL),
    ("iosxr.conf", "snmp-server group NETOPS v3 priv", Status.PASS),
    ("huawei.conf", "snmp-agent group v3 NMS authentication read-view iso", Status.FAIL),
    ("huawei.conf", "snmp-agent group v3 NMS privacy", Status.PASS),
], ids=lambda v: v if isinstance(v, str) and v.endswith(".conf") else None)
def test_snmpv3_level_is_read_decisively(seeded_adaptive_db, name, line, expected):
    assert _statuses(_with(name, line), "MGMT-012") == {(expected, Assurance.CONFIRMED)}


def test_one_weak_group_fails_beside_a_strong_one(seeded_adaptive_db):
    text = _with("arista.conf", "snmp-server group A v3 priv", "snmp-server group B v3 noauth")
    results = analyze_generic_text(text).control("MGMT-012")
    assert [r.status for r in results] == [Status.FAIL]
    assert results[0].failure.severity.value == "high"  # noAuthNoPriv


@pytest.mark.parametrize("line, expected", [
    ("ssl server-version tlsv1", Status.FAIL),
    ("ssl server-version tlsv1.1 dtlsv1", Status.FAIL),
    ("ssl server-version tlsv1.2", Status.PASS),
    ("ssl server-version tlsv1.2 dtlsv1.2", Status.PASS),
])
def test_asa_minimum_tls_version(seeded_adaptive_db, line, expected):
    assert _statuses(_with("asa.conf", line), "CRYPTO-003") == {(expected, Assurance.CONFIRMED)}


def test_asa_client_version_is_not_the_server(seeded_adaptive_db):
    assert _status(_with("asa.conf", "ssl client-version tlsv1"), "CRYPTO-003") == {Status.NOT_CONFIGURED}


# ── absence of the feature ───────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["arista.conf", "asa.conf", "huawei.conf", "junos.conf", "panos.conf", "exos.conf"])
def test_understood_configuration_without_the_feature_is_not_applicable(seeded_adaptive_db, name):
    text = (REFERENCE / name).read_text(encoding="utf-8")
    assert _status(text, "MGMT-012") == {Status.N_A}
    assert _status(text, "BOUNDARY-006") == {Status.N_A}


@pytest.mark.parametrize("name, line", [
    ("arista.conf", "router bgp 65001"),
    ("junos.conf", "set protocols ospf area 0.0.0.0 interface ge-0/0/1.0"),
    ("huawei.conf", "ospf 1 router-id 1.1.1.1"),
])
def test_a_routing_protocol_keeps_routing_auth_undecided(seeded_adaptive_db, name, line):
    """Nothing reads BGP / OSPF authentication on these dialects yet: undecided, never N/A and never PASS."""
    assert _status(_with(name, line), "BOUNDARY-006") == {Status.NOT_CONFIGURED}


@pytest.mark.parametrize("name, line", [
    ("arista.conf", "snmp-server user mon NETOPS v3 auth sha <SECRET:snmp>"),
    ("junos.conf", "set snmp v3 usm local-engine user mon authentication-sha"),
    ("exos.conf", "configure snmpv3 add access NETOPS sec-model usm sec-level authnopriv"),
])
def test_snmpv3_in_an_unread_form_keeps_the_check_undecided(seeded_adaptive_db, name, line):
    assert _status(_with(name, line), "MGMT-012") == {Status.NOT_CONFIGURED}


def test_unknown_text_is_never_not_applicable(seeded_adaptive_db):
    """Absence counts only in a configuration some dialect's knowledge understands."""
    text = "hostname box\nfoo bar baz\nqux 1 2 3\n"
    assert _status(text, "MGMT-012") == {Status.NOT_CONFIGURED}
    assert _status(text, "BOUNDARY-006") == {Status.NOT_CONFIGURED}


def test_tls_absence_is_never_read(seeded_adaptive_db):
    """HTTPS management is on by default on many platforms: an unstated TLS version stays undecided."""
    assert _status((REFERENCE / "asa.conf").read_text(encoding="utf-8"), "CRYPTO-003") == {Status.NOT_CONFIGURED}
