"""Checks across devices (app/analysis/fleet_checks.py): decided facts only, and a shared secret is never shown."""

import json
from pathlib import Path
from types import SimpleNamespace as NS

from app.analysis.fleet_checks import fleet_findings
from app.api.routes.scan import run_scan

DEMO = Path(__file__).resolve().parents[2] / "backend" / "tests" / "fixtures" / "demo"


def _fact(predicate, value, assurance="parser", lines=(1,)):
    return NS(predicate=predicate, value=value, assurance=NS(value=assurance), evidence=NS(line_numbers=list(lines)))


def _snmp(name, **kw):
    return _fact("snmp.community", {"name": name, "permission": "RO"}, **kw)


def test_a_community_shared_by_devices_is_reported_without_its_value():
    [finding] = fleet_findings([[_snmp("s3cret", lines=[4])], [_snmp("s3cret", lines=[9])], [_snmp("other")]])
    assert finding["check"] == "shared-snmp-community"
    assert [(d["config_index"], d["lines"]) for d in finding["devices"]] == [(0, [4]), (1, [9])]
    assert "s3cret" not in json.dumps(finding)


def test_only_decided_facts_count_and_one_device_is_not_a_fleet():
    assert fleet_findings([[_snmp("x")], [_snmp("x", assurance="heuristic")]]) == []
    assert fleet_findings([[_snmp("x"), _snmp("x")]]) == []


def test_ntp_servers_are_compared_as_sets():
    ntp = lambda *s: [_fact("time.ntp.server", list(s))]
    assert fleet_findings([ntp("a", "b"), ntp("b", "a")]) == []
    [finding] = fleet_findings([ntp("a"), ntp("b"), []])  # a device stating nothing is left out
    assert finding["check"] == "ntp-mismatch" and [d["value"] for d in finding["devices"]] == ["a", "b"]


def test_the_demo_pair_shares_a_community_and_disagrees_on_ntp(seeded_adaptive_db):
    scan = run_scan([(n, (DEMO / n).read_text()) for n in ("cisco_edge_vulnerable.cfg", "paloalto_fw_vulnerable.cfg")])
    assert [f["check"] for f in scan.fleet_findings] == ["shared-snmp-community", "ntp-mismatch"]
    assert '"public"' not in json.dumps(scan.fleet_findings)
