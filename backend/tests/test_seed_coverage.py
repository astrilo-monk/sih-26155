"""
Seed coverage per dialect: how many of the 23 checks shipped knowledge decides when a configuration states them.

Three layers, as for every seed: the lines each new seed reads (and the near-miss lines it must not read), the engine
rules that keep those readings honest (documented defaults, top-level and chained scopes, interface-local settings,
IPsec proposals stated one algorithm per line), and the per-dialect floor measured by ``scripts/seed_coverage.py``
on the reference configurations in ``tests/fixtures/seed_coverage/``. Sources are listed in docs/seed-knowledge.md.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from app.controls.evaluate import evaluate_controls
from app.facts.recognizers import recognizer_facts
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Status
from app.structure.tokenizer import tokenize

BACKEND = Path(__file__).resolve().parents[1]
REFERENCE = BACKEND / "tests" / "fixtures" / "seed_coverage"
CASES = json.loads((REFERENCE / "line_cases.json").read_text(encoding="utf-8"))
DECISIVE = {Assurance.PARSER, Assurance.CONFIRMED, Assurance.DEFAULT}

# decided checks out of 23, per dialect, on its reference configuration. A dialect below 18 (75 %) is held back by
# what the template engine cannot read or what no source documents; docs/seed-knowledge.md says which, per check.
FLOOR = {
    "Juniper Junos": 20, "Palo Alto PAN-OS": 20, "Extreme Networks EXOS": 19, "Arista EOS": 18, "Cisco NX-OS": 18,
    "Huawei VRP": 18, "Check Point Gaia": 18, "Cisco ASA": 16, "MikroTik RouterOS": 15, "HPE Aruba AOS-CX": 15,
    "Dell OS10": 13, "VyOS": 13, "Cisco IOS-XR": 12, "Fortinet FortiSwitchOS": 12,
}


def _values(text: str, predicate: str, subject=None) -> list:
    return [f.value for f in recognizer_facts(text.splitlines())[0]
            if f.predicate == predicate and (subject is None or f.subject == subject)]


def _results(text: str) -> dict:
    config = NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN), raw_config=text, raw_lines=text.splitlines())
    out = {}
    for r in evaluate_controls(config):
        out.setdefault(r.control_id, []).append(r)
    return out


def _decided(text: str, control_id: str):
    """'pass' / 'fail' when decisive, else None."""
    results = _results(text)[control_id]
    if all(r.status in (Status.PASS, Status.FAIL) and r.assurance in DECISIVE for r in results):
        return "fail" if any(r.status == Status.FAIL for r in results) else "pass"
    return None


# ── every new seed: what it reads, and what it must not ────────────────────────

@pytest.mark.parametrize("case", CASES, ids=[f"{c['predicate']}:{c['lines'][:40]}" for c in CASES])
def test_each_seed_reads_its_line_and_nothing_near_it(seeded_adaptive_db, case):
    got = _values(case["lines"], case["predicate"], case["subject"])
    expected = case["expect"]
    # "None": the line is read and its value stays undetermined (an interface-local setting)
    assert got == ([] if expected is None else [None] if expected == "None" else [expected])


# ── the per-dialect floor ──────────────────────────────────────────────────────

def test_every_dialect_keeps_its_measured_coverage(seeded_adaptive_db):
    spec = importlib.util.spec_from_file_location("seed_coverage", BACKEND / "scripts" / "seed_coverage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    measured = module.measure(isolate=False)
    assert set(measured) == set(FLOOR)
    for dialect, floor in FLOOR.items():
        assert measured[dialect]["count"] >= floor, (dialect, measured[dialect]["undecided"])
        assert measured[dialect]["vendor_status"] != "confirmed", dialect  # read by seeds, never by a parser
    assert sum(m["count"] >= 18 for m in measured.values()) == 7


# ── documented defaults ────────────────────────────────────────────────────────

NXOS = "hostname NX\nfeature lldp\nlogging server 192.0.2.50\ntacacs-server host 192.0.2.60\nuserpassphrase min-length 15\n"


def test_a_documented_default_decides_a_silent_setting(seeded_adaptive_db):
    ssh = _results(NXOS)["MGMT-007"][0]
    assert ssh.status == Status.PASS and ssh.assurance == Assurance.DEFAULT
    assert "supports only SSH version 2" in ssh.reason


def test_a_line_naming_the_setting_stops_the_default(seeded_adaptive_db):
    # an SSH version line no seed reads may be the one changing the default: undecided, never the default
    assert _decided(NXOS + "ssh protocol version 1\n", "MGMT-007") is None


def test_a_line_already_read_as_another_setting_does_not_stop_the_default(seeded_adaptive_db):
    asa = ("ASA Version 9.16(4)\nhostname FW\nssh version 2\nlogging host inside 192.0.2.50\naaa local authentication "
           "attempts max-fail 3\ntelnet timeout 5\n")
    telnet = _results(asa)["MGMT-001"][0]
    assert telnet.status == Status.PASS and telnet.assurance == Assurance.DEFAULT
    # a Telnet access line is not explained by anything: the default no longer speaks
    assert _decided(asa + "telnet 10.0.0.0 255.0.0.0 inside\n", "MGMT-001") is None


def test_a_default_that_fails_says_where_it_comes_from(seeded_adaptive_db):
    asa = "ASA Version 9.16(4)\nhostname FW\nssh version 2\nlogging host inside 192.0.2.50\nssh timeout 5\n"
    crypto = _results(asa)["CRYPTO-002"][0]
    assert crypto.status == Status.FAIL and crypto.assurance == Assurance.DEFAULT
    custom = asa + "ssh cipher encryption custom aes128-ctr:aes192-ctr:aes256-ctr\n"
    assert _decided(custom, "CRYPTO-002") == "pass"


# ── scopes ─────────────────────────────────────────────────────────────────────

def test_a_top_level_scope_never_reads_the_same_words_inside_a_block(seeded_adaptive_db):
    assert _values("exec-timeout 300", "mgmt.session.idle_timeout") == [5.0]          # Dell OS10, seconds
    assert _values("line vty\n  exec-timeout 15", "mgmt.session.idle_timeout") == [15.0]  # NX-OS, minutes


def test_a_scope_chain_names_the_table_an_edit_block_belongs_to(seeded_adaptive_db):
    community = 'config system snmp community\n    edit 1\n        set name "public"\n    next\nend'
    assert _values(community, "snmp.community") == [{"name": "public", "permission": "RO", "acl": None}]
    vlan = 'config switch vlan\n    edit 10\n        set name "public"\n    next\nend'
    assert _values(vlan, "snmp.community") == []


# ── interface-local settings decide nothing about the others ──────────────────

def test_lldp_off_on_one_interface_is_read_and_left_undecided(seeded_adaptive_db):
    text = "hostname SW\nlldp run\ninterface Ethernet1\n   no lldp transmit\n"
    assert _values(text, "boundary.discovery_protocol.enabled", "lldp") == [True, None]
    assert _decided(text, "BOUNDARY-003") is None
    # on an interface an external zone holds it is decided
    pan = "set zone untrust network layer3 ethernet1/1\nset network interface ethernet ethernet1/1 layer3 lldp enable no\n"
    assert _values(pan, "boundary.discovery_protocol.enabled", "lldp") == [False]


def test_redirects_off_on_one_interface_is_not_a_pass(seeded_adaptive_db):
    one = "interface Ethernet1/1\n  no ip redirects\n"
    assert _values(one, "boundary.interface.unsafe_service", "redirects") == [None]
    # switched off for the whole device it is
    assert _values("set system no-redirects", "boundary.interface.unsafe_service", "redirects") == [False]
    # switched on anywhere it fails
    on = "interface Ethernet1/1\n  no ip redirects\n  ip proxy-arp\n"
    assert _values(on, "boundary.interface.unsafe_service", "proxy-arp") == [True]
    assert _decided(on, "BOUNDARY-004") == "fail"


# ── IPsec proposals stated one algorithm per line ─────────────────────────────

def test_a_weak_algorithm_on_any_line_of_a_proposal_fails(seeded_adaptive_db):
    junos = ("set system host-name EDGE\nset system syslog host 192.0.2.50 any notice\nset system ntp server 192.0.2.10\n"
             "set system login message \"x\"\n"
             "set security ike proposal P1 encryption-algorithm aes-256-cbc\nset security ike proposal P1 dh-group group2\n")
    assert _decided(junos, "CRYPTO-001") == "fail"
    strong = junos.replace("group2", "group14")
    assert _decided(strong, "CRYPTO-001") == "pass"


# ── the tokenizer: ASA banners are one line each ───────────────────────────────

def test_an_asa_banner_does_not_swallow_the_lines_after_it():
    statements = tokenize(["banner login Authorized access only", "logging host inside 192.0.2.50", "ASA Version 9.16"])
    assert [s.line for s in statements] == [1, 2, 3]
    # a delimited multi-line banner still hides its body
    statements = tokenize(["banner motd ^C", "logging host 1.2.3.4", "^C", "hostname X"])
    assert [s.line for s in statements] == [1, 4]


# ── weak algorithms add up; banners add up ─────────────────────────────────────

def test_one_weak_cipher_among_strong_ones_is_weak(seeded_adaptive_db):
    text = "set system services ssh ciphers aes256-ctr\nset system services ssh ciphers aes128-cbc\n"
    assert _values(text, "mgmt.crypto.weak_allowed") == [True]


def test_one_banner_shown_is_a_banner(seeded_adaptive_db):
    text = "banner motd disable\nbanner login ^C\nAuthorized access only\n^C\n"
    assert _values(text, "banner.login.present") == [True]
