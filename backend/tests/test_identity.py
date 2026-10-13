"""
Device identity from command output (``app.facts.identity``): the serial number and hardware the problem
statement asks the report to carry, read from ``show version``-style output uploaded or collected with a
configuration. Output is never scanned as a device, and never tied to a configuration on a guess.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import app.config as app_config
from app.collect.collector import Collected
from app.facts.identity import is_command_output, output_hostname, pair_outputs, stated_identity
from app.main import app

IOS_CONFIG = """hostname core-01
version 15.2
service password-encryption
enable secret 5 $1$abc$xyz
no ip http server
ip ssh version 2
line vty 0 4
 transport input ssh
 exec-timeout 10 0
!
end
"""

# written for these tests in the shape each command prints; no device's real output
IOS_SHOW_VERSION = """Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)E10, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
ROM: Bootstrap program is C3750E boot loader
core-01 uptime is 12 weeks, 3 days, 4 hours, 10 minutes
System image file is "flash:c3750e-universalk9-mz.152-4.E10.bin"
cisco WS-C3750X-48P (PowerPC405) processor (revision W0) with 262144K bytes of memory.
Processor board ID FDO1111A2BC
Model number                    : WS-C3750X-48P-S
System serial number            : FDO1111A2BC
"""

OUTPUTS = {
    "junos": ("""Hostname: edge-01
Model: mx204
Junos: 21.4R3-S5
JUNOS OS Kernel 64-bit  [20230321.f4e3d2a_builder_stable_12]

Hardware inventory:
Item             Version  Part number  Serial number     Description
Chassis                                JN1234567ABC      MX204
""", {"serial": "JN1234567ABC", "model": "mx204", "os_version": "21.4R3-S5"}),
    "fortios": ("""Version: FortiGate-100F v7.0.12,build0523,230613 (GA.M)
Serial-Number: FG100FTK20000001
Hostname: fw-01
Operation Mode: NAT
""", {"serial": "FG100FTK20000001", "model": "FortiGate-100F", "os_version": "7.0.12"}),
    "panos": ("""hostname: pa-01
ip-address: 10.0.0.5
model: PA-3220
serial: 012345678901
sw-version: 10.1.6
""", {"serial": "012345678901", "model": "PA-3220", "os_version": "10.1.6"}),
    "arista": ("""Arista DCS-7050SX3-48YC8-R
Hardware version: 11.02
Serial number: JPE20000001
System MAC address: 001c.7300.0001

Software image version: 4.28.3M
""", {"serial": "JPE20000001", "model": "DCS-7050SX3-48YC8-R", "os_version": "4.28.3M"}),
}


@pytest.fixture
def client():
    return TestClient(app)


def _upload(client, *files):
    return client.post("/api/scan", files=[("files", (name, text.encode(), "text/plain")) for name, text in files])


# -- reading ----------------------------------------------------------------------------------

def test_cisco_show_version_states_serial_model_and_full_version():
    assert is_command_output(IOS_SHOW_VERSION)
    assert output_hostname(IOS_SHOW_VERSION) == "core-01"
    assert stated_identity(IOS_SHOW_VERSION.splitlines(), output=True) == {
        "os_version": "15.2(4)E10", "model": "WS-C3750X-48P", "serial": "FDO1111A2BC"}


@pytest.mark.parametrize("vendor", sorted(OUTPUTS))
def test_each_vendors_identity_command_is_read(vendor):
    text, expected = OUTPUTS[vendor]
    assert is_command_output(text), vendor
    assert stated_identity(text.splitlines(), output=True) == expected


@pytest.mark.parametrize("config", [
    IOS_CONFIG,
    "set chassis cluster reth-count 2\nset system host-name fw\nset system services ssh\n",
    "config system global\n    set hostname fw-01\nend\n",
])
def test_a_configuration_is_not_command_output(config):
    assert not is_command_output(config)


def test_output_only_lines_are_never_read_from_a_configuration():
    """In a configuration, ``chassis cluster`` is not a serial number."""
    assert "serial" not in stated_identity(["Chassis CLUSTER1234 enabled"])


# -- pairing ----------------------------------------------------------------------------------

def test_an_output_pairs_by_the_hostname_it_states():
    assert pair_outputs([("x.txt", IOS_SHOW_VERSION)], [("a.cfg", "edge"), ("b.cfg", "core-01")]) == {0: 1}


def test_an_output_pairs_by_file_name_and_the_longest_name_wins():
    configs = [("core.cfg", "r1"), ("core-01.cfg", "r2"), ("core-011.cfg", "r3")]
    assert pair_outputs([("core-01-show-version.txt", "")], configs) == {0: 1}


def test_an_output_naming_another_device_is_not_attached():
    assert pair_outputs([("x.txt", IOS_SHOW_VERSION)], [("a.cfg", "edge")]) == {0: None}


def test_with_several_configurations_and_no_clue_nothing_is_guessed():
    assert pair_outputs([("version.txt", "Serial number: X1234\n")], [("a.cfg", "r1"), ("b.cfg", "r2")]) == {0: None}


# -- the scan ---------------------------------------------------------------------------------

def test_uploaded_show_version_fills_the_device_and_is_not_a_device(client):
    resp = _upload(client, ("core-01.cfg", IOS_CONFIG), ("core-01-version.txt", IOS_SHOW_VERSION))
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    assert len(scan["devices"]) == 1
    device = scan["devices"][0]
    assert device["serial"] == "FDO1111A2BC" and device["model"] == "WS-C3750X-48P"
    # the configuration said 15.2; the output says which 15.2
    assert device["os_version"] == "15.2(4)E10"
    assert device["identity_source"] == "core-01-version.txt"
    assert scan["unpaired_outputs"] == []


def test_identity_output_changes_no_verdict(client):
    verdicts = lambda s: {(r["control_id"], r["scope"]): r["status"] for r in s["results"]}
    alone = _upload(client, ("core-01.cfg", IOS_CONFIG)).json()
    paired = _upload(client, ("core-01.cfg", IOS_CONFIG), ("v.txt", IOS_SHOW_VERSION)).json()
    assert verdicts(alone) == verdicts(paired) and alone["posture"] == paired["posture"]


def test_an_output_matching_no_configuration_is_reported(client):
    other = IOS_SHOW_VERSION.replace("core-01 uptime", "dist-09 uptime")
    scan = _upload(client, ("core-01.cfg", IOS_CONFIG), ("dist-09.txt", other)).json()
    assert scan["devices"][0]["serial"] is None
    assert scan["unpaired_outputs"] == ["dist-09.txt"]


def test_output_alone_is_refused_with_a_reason(client):
    resp = _upload(client, ("version.txt", IOS_SHOW_VERSION))
    assert resp.status_code == 400 and "configuration" in resp.json()["detail"]


def test_a_collected_device_reports_what_its_identity_command_said(client, monkeypatch):
    monkeypatch.setattr(app_config.settings, "live_collection_enabled", True)
    collected = Collected(IOS_CONFIG, IOS_SHOW_VERSION, "'show version' on 10.0.0.1")
    with patch("app.api.routes.collect.collect", return_value=collected):
        resp = client.post("/api/collect", json={"targets": [
            {"host": "10.0.0.1", "platform": "cisco_ios", "username": "u", "password": "p"}]})
    device = resp.json()["scan"]["devices"][0]
    assert device["serial"] == "FDO1111A2BC"
    assert device["identity_source"] == "'show version' on 10.0.0.1"


def test_every_identity_command_is_read_only():
    from app.collect.collector import PLATFORMS

    for spec in PLATFORMS.values():
        for command in spec.identity:
            assert command.split()[0] in ("show", "get", "display", "/system"), command
            assert "print" in command or not command.startswith("/"), command


@pytest.mark.parametrize("text", [
    "\n" * 2_000_000,                         # a pattern that crossed newlines rescanned the rest per line
    "Model: x\n" * 200_000,                   # a lookahead over the whole file per matching line
    "Cisco " + "Software, " * 200_000,        # two unbounded runs on one line
    "model" + " " * 2_000_000,                # adjacent whitespace quantifiers on one long line
], ids=["blank-lines", "model-lines", "cisco-line", "long-line"])
def test_a_hostile_upload_is_read_in_linear_time(text):
    """2 MB is the upload limit; every path through the identity patterns must stay linear in it."""
    import time

    start = time.perf_counter()
    is_command_output(text)
    output_hostname(text)
    stated_identity(text.splitlines(), output=True)
    assert time.perf_counter() - start < 20
