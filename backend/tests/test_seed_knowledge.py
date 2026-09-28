"""
Shipped seed knowledge -recognizers NetAuditAI deploys with, so an unfamiliar dialect already
answers several controls before an administrator teaches anything.

Every test here runs against ``seeded_adaptive_db``: the isolated database as a fresh deployment
sees it. The rest of the suite deliberately runs without seeds, so it keeps proving what the
generic engine works out on its own.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.adaptive.matcher import EXTRACTION_RECOGNIZER
from app.controls.evaluate import evaluate_controls
from app.db import database
from app.db.mappings import (
    SOURCE_RUNTIME, SOURCE_SEED, LearnedMapping, MappingRepository,
)
from app.facts.from_normalized import facts_from_config
from app.facts.predicates import PREDICATES, PROTOCOL_ENABLED, SSH_VERSION
from app.facts.recognizers import recognizer_facts
from app.facts.seed import load_seed_recognizers, read_seed_file
from app.main import app
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Status

BACKEND = Path(__file__).resolve().parents[1]
DIALECTS = BACKEND / "tests" / "fixtures" / "seed_dialects"
FIXTURES = BACKEND / "tests" / "fixtures"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _unknown(text: str) -> NormalizedConfig:
    return NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="seed"),
                            raw_config=text, raw_lines=text.splitlines())


def _facts(text: str) -> list:
    return recognizer_facts(text.splitlines())[0]


def _telnet(text: str):
    """The value the seed knowledge reads for 'is Telnet reachable', or None."""
    return next((f.value for f in _facts(text) if f.predicate == PROTOCOL_ENABLED and f.subject == "telnet"), None)


def _results(text: str) -> dict:
    return {r.control_id: r for r in evaluate_controls(_unknown(text))}


def _runtime_recognizer(**overrides) -> LearnedMapping:
    values = dict(
        concept="Telnet", normalized_field="", extraction_method=EXTRACTION_RECOGNIZER, confirmed=True,
        predicate=PROTOCOL_ENABLED, subject="telnet", command_pattern="remote-console protocol {enum:protocol}",
        constant_value='{"telnet": true, "*": false}', example_line="remote-console protocol telnet",
    )
    values.update(overrides)
    return LearnedMapping(**values)


# ── 1–3, 12: loading ────────────────────────────────────────────────────────

def test_a_fresh_database_loads_the_shipped_seed_knowledge(seeded_adaptive_db):
    stored = MappingRepository().list_mappings()
    assert len(stored) == len(read_seed_file())
    assert {m.source for m in stored} == {SOURCE_SEED}
    assert all(m.confirmed and m.active and m.extraction_method == EXTRACTION_RECOGNIZER for m in stored)
    # every shipped entry answers a predicate a control consumes
    assert {m.predicate for m in stored} <= PREDICATES


def test_loading_the_seed_again_changes_nothing(seeded_adaptive_db):
    before = MappingRepository().list_mappings(include_inactive=True)
    assert load_seed_recognizers(seeded_adaptive_db) == 0
    assert load_seed_recognizers(seeded_adaptive_db) == 0
    assert MappingRepository().list_mappings(include_inactive=True) == before


def test_seed_loading_never_touches_what_an_administrator_confirmed(seeded_adaptive_db):
    repository = MappingRepository()
    learned = repository.save_mapping(_runtime_recognizer())
    assert learned.source == SOURCE_RUNTIME

    # an administrator's judgement on a shipped recognizer also survives a reload
    seed = next(m for m in repository.list_mappings() if m.command_pattern == "telnet server {polarity}")
    repository.disable_mapping(seed.id, actor="admin")
    edited = repository.update_mapping(
        next(m for m in repository.list_mappings() if m.command_pattern == "logging host {host} {rest}").id,
        {"concept": "Syslog (site wording)"}, actor="admin")

    assert load_seed_recognizers(seeded_adaptive_db) == 0
    after = {m.id: m for m in MappingRepository().list_mappings(include_inactive=True)}
    assert after[learned.id] == learned
    assert after[seed.id].active is False
    assert after[edited.id].concept == "Syslog (site wording)"


def test_a_seed_entry_colliding_with_a_learned_pattern_is_skipped(seeded_adaptive_db):
    repository = MappingRepository()
    shipped = next(m for m in repository.list_mappings() if m.command_pattern == "ntp server {host} {rest}")
    repository.disable_mapping(shipped.id, actor="admin")
    # the site now owns that pattern with its own wording
    repository.save_mapping(_runtime_recognizer(
        concept="Site NTP", predicate="time.ntp.server", subject=None, command_pattern="ntp server {host} {rest}",
        constant_value=None, example_line="ntp server 192.0.2.10"))

    assert load_seed_recognizers(seeded_adaptive_db) == 0
    owners = [m.source for m in MappingRepository().list_mappings() if m.command_pattern == "ntp server {host} {rest}"]
    assert owners == [SOURCE_RUNTIME]


def test_runtime_learning_and_seed_knowledge_both_survive_a_new_process(tmp_path):
    db = tmp_path / "persistent.db"
    database._SEEDED.discard(db)
    MappingRepository(db).save_mapping(_runtime_recognizer())

    code = ("import json;"
            "from app.db.mappings import MappingRepository;"
            "print(json.dumps([m.source for m in MappingRepository().list_mappings()]))")
    env = {**os.environ, "ADAPTIVE_DB_PATH": str(db), "DATABASE_URL": ""}
    done = subprocess.run([sys.executable, "-c", code], cwd=BACKEND, env=env, capture_output=True, text=True,
                          timeout=180)
    assert done.returncode == 0, done.stderr
    sources = json.loads(done.stdout.strip().splitlines()[-1])
    assert sources.count(SOURCE_RUNTIME) == 1
    assert sources.count(SOURCE_SEED) == len(read_seed_file())


# ── 4–6: the recognizers generalize, and only where they should ─────────────

@pytest.mark.parametrize("name", ["junos.conf", "panos.conf", "huawei.conf", "routeros.rsc"])
def test_one_concept_is_read_from_materially_different_dialects(seeded_adaptive_db, name):
    assert _telnet(_text(DIALECTS / name)) is True


@pytest.mark.parametrize("name", ["junos.conf", "panos.conf", "arista.conf", "huawei.conf", "routeros.rsc",
                                  "gaia.conf", "exos.conf", "aruba.conf",
                                  "nxos.conf", "asa.conf", "iosxr.conf", "junos_set.conf"])
def test_every_shipped_dialect_contributes_decisive_facts(seeded_adaptive_db, name):
    facts = _facts(_text(DIALECTS / name))
    assert len(facts) >= 3
    assert all(f.assurance == Assurance.CONFIRMED and f.evidence.line_numbers for f in facts)


@pytest.mark.parametrize("config, expected", [
    # different addresses, names, numbers, indentation and block placement
    ("system {\n  services {\n      telnet;\n  }\n}\n", True),
    ("system {\n\tservices {\n\t\ttelnet;\n\t}\n}\n", True),
    ("telnet server enable\n", True),
    ("telnet server disable\n", False),
    ("/ip service\nset telnet disabled=no\n", True),
    ("/ip service\nset telnet disabled=yes\n", False),
    ("set deviceconfig system service disable-telnet no\n", True),
    ("set deviceconfig system service disable-telnet yes\n", False),
])
def test_changed_values_and_layout_do_not_break_recognition(seeded_adaptive_db, config, expected):
    assert _telnet(config) is expected


@pytest.mark.parametrize("config", [
    # a traffic rule mentions Telnet without configuring management access
    "set rulebase security rules Block-Telnet application telnet action deny\n",
    "firewall {\n  filter BLOCK {\n    term T {\n      destination-port telnet;\n    }\n  }\n}\n",
    # the same leaf word outside the block that gives it its meaning
    "system {\n  applications {\n    telnet;\n  }\n}\n",
    "/ip firewall filter\nset telnet disabled=no\n",
    # a description is not a setting
    "description \"telnet server enable\"\n",
])
def test_unrelated_lines_never_trigger_a_seed_recognizer(seeded_adaptive_db, config):
    assert _telnet(config) is None


@pytest.mark.parametrize("config, predicate, expected", [
    # taught from teach/: a login banner, an any-any rule, a management source restriction
    ("banner login\n", "banner.login.present", True),
    ("configure banner before-login\n", "banner.login.present", True),
    ("ip access-list WAN-IN\n   10 permit ip any any\n", "boundary.policy.permit_any", True),
    ("access-list ip EDGE-IN\n    10 permit any any\n", "boundary.policy.permit_any", True),
    ("management ssh\n   ip access-group MGMT-IN in\n", "mgmt.remote_access.source_restricted", True),
    ("system {\n  login {\n    profile OPS {\n      allow-address 192.0.2.0/24;\n    }\n  }\n}\n",
     "mgmt.remote_access.source_restricted", True),
    ("set network profiles interface-management-profile MGMT permitted-ip 192.0.2.0/24\n",
     "mgmt.remote_access.source_restricted", True),
    # second pass over teach/: every dialect, every setting its five files state
    ("system {\n  login {\n    message \"Authorized access only.\";\n  }\n}\n", "banner.login.present", True),
    ("system {\n  authentication-order [ tacplus password ];\n}\n", "auth.central_aaa.enabled", True),
    # Junos takes one method without the brackets just as readily
    ("system {\n  authentication-order tacplus;\n}\n", "auth.central_aaa.enabled", True),
    ("system {\n  authentication-order radius;\n}\n", "auth.central_aaa.enabled", True),
    ('set deviceconfig system login-banner "Authorized access only."\n', "banner.login.present", True),
    ("set deviceconfig system session-timeout 10\n", "mgmt.session.idle_timeout", 10.0),
    ("set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key\n",
     "time.ntp.authenticated", True),
    ("set deviceconfig system ntp-servers primary-ntp-server authentication-type none\n",
     "time.ntp.authenticated", False),
    ("set deviceconfig system permitted-ip 192.0.2.0/24\n", "mgmt.remote_access.source_restricted", True),
    ("aaa authentication login default local\n", "auth.central_aaa.enabled", False),
    ("username ops privilege 15 role network-admin secret 0 <SECRET:type0>\n", "auth.password.storage", "plaintext"),
    ("username ops privilege 15 secret sha512 <SECRET:password>\n", "auth.password.storage", "hashed"),
    ('header login information "Authorized access only."\n', "banner.login.present", True),
    ("undo lldp enable\n", "boundary.discovery_protocol.enabled", False),
    ("aaa\n local-user ops password irreversible-cipher <SECRET:password>\n", "auth.password.storage", "hashed"),
    ("aaa\n local-user ops password simple <SECRET:password>\n", "auth.password.storage", "plaintext"),
    ("acl number 2000\n rule 5 permit source any\n", "boundary.policy.permit_any", True),
    ("acl number 2040\n rule 10 permit\n", "boundary.policy.permit_any", True),
    ("logging 192.0.2.20\n", "log.remote.destination", ["192.0.2.20"]),
    ("user ops group administrators password plaintext <SECRET:password>\n", "auth.password.storage", "plaintext"),
    ("enable telnet\n", "mgmt.remote_access.protocol_enabled", True),
    ("disable web\n", "mgmt.remote_access.protocol_enabled", False),
    ("configure ssh2 inactivity-timeout 600\n", "mgmt.session.idle_timeout", 10.0),
    ("configure account ops encrypted <SECRET:password>\n", "auth.password.storage", "encrypted"),
    ("configure ssh2 access-profile MGMT-SSH\n", "mgmt.remote_access.source_restricted", True),
    ("set telnet-server enabled true\n", "mgmt.remote_access.protocol_enabled", True),
    ("set web-server enabled false\n", "mgmt.remote_access.protocol_enabled", False),
    ("set lldp enabled true\n", "boundary.discovery_protocol.enabled", True),
    ("set source-routing enabled\n", "boundary.source_routing.enabled", True),
    ("set ssh server session-timeout 900\n", "mgmt.session.idle_timeout", 15.0),
    ('set login-banner "Lab gateway"\n', "banner.login.present", True),
    ("set access-rule 10 source any destination any service any action accept\n", "boundary.policy.permit_any", True),
    ('/system note set show-at-login=yes note="Authorized only."\n', "banner.login.present", True),
    ("/interface lldp set [find] disabled=no\n", "boundary.discovery_protocol.enabled", True),
    ("/ip firewall filter\nadd chain=input action=accept\n", "boundary.policy.permit_any", True),
    # from Batfish's test configs: servers with trailing options ({rest}), NX-OS, ASA, IOS-XR, set-style Junos
    ("logging host 192.0.2.20 514 protocol udp\n", "log.remote.destination", ["192.0.2.20"]),
    ("logging vrf MGMT host 192.0.2.20 514 protocol udp\n", "log.remote.destination", ["192.0.2.20"]),
    ("logging server 192.0.2.20 5 use-vrf management\n", "log.remote.destination", ["192.0.2.20"]),
    ("logging host inside 192.0.2.20 udp/514\n", "log.remote.destination", ["192.0.2.20"]),
    ("logging 192.0.2.20 vrf mgmt severity info\n", "log.remote.destination", ["192.0.2.20"]),
    ("set system syslog host 192.0.2.20 any notice\n", "log.remote.destination", ["192.0.2.20"]),
    ("ntp server 192.0.2.10 key 1 prefer\n", "time.ntp.server", ["192.0.2.10"]),
    ("system {\n  ntp {\n    server 192.0.2.10 key 1;\n  }\n}\n", "time.ntp.server", ["192.0.2.10"]),
    ("set system ntp server 192.0.2.10 key 1\n", "time.ntp.server", ["192.0.2.10"]),
    ("tacacs-server host 192.0.2.30 key 7 <SECRET:type7>\n", "auth.central_aaa.enabled", True),
    ("no tacacs-server host 192.0.2.30\n", "auth.central_aaa.enabled", False),
    ("set system tacplus-server 192.0.2.30 timeout 5\n", "auth.central_aaa.enabled", True),
    ("set system login class OPS idle-timeout 10\n", "mgmt.session.idle_timeout", 10.0),
    ("line vty\n  exec-timeout 10\n", "mgmt.session.idle_timeout", 10.0),
    ("ip access-list ANY-IN\n  permit ip any any\n", "boundary.policy.permit_any", True),
    ("access-list OUTSIDE_IN extended permit ip any any\n", "boundary.policy.permit_any", True),
    # PAN-OS from Batfish's test configs: LLDP per interface, TACACS+ / RADIUS server profiles
    ("set network interface ethernet ethernet1/1 layer3 lldp enable no\n",
     "boundary.discovery_protocol.enabled", False),
    ("set network interface ethernet ethernet1/3 layer3 lldp enable yes\n",
     "boundary.discovery_protocol.enabled", True),
    ("set shared server-profile tacplus TAC-MGMT server TAC1 address 192.0.2.30\n", "auth.central_aaa.enabled", True),
    ("set shared server-profile radius RAD-MGMT server RAD1 ip-address 192.0.2.31\n", "auth.central_aaa.enabled", True),
    ("set shared log-settings syslog SL1 server S1 server 192.0.2.20\n", "log.remote.destination", ["192.0.2.20"]),
    ("set vsys vsys1 log-settings syslog SG1 server S1 server 192.0.2.21\n",
     "log.remote.destination", ["192.0.2.21"]),
    ("set mgt-config users ops phash $1$vqgaovyp$BA8m4uld.cxY2T/n9ihK2.\n", "auth.password.storage", "hashed"),
    ("set mgt-config users ops public-key c3NoLXJzYQ==\n", "auth.password.storage", None),
    ("set vsys vsys1 log-settings syslog SG1 server S1 facility LOG_LOCAL0\n", "log.remote.destination", None),
    # set-style Junos, as Batfish's Junos configs write it
    ("set system services telnet\n", "mgmt.remote_access.protocol_enabled", True),
    ("set system services web-management http interface fxp0.0\n", "mgmt.remote_access.protocol_enabled", True),
    ("set system services web-management https system-generated-certificate\n",
     "mgmt.remote_access.protocol_enabled", None),
    ("set system services ssh protocol-version v1\n", "mgmt.ssh.version", 1),
    ("set system login class OPS allow-sources 192.0.2.0/24\n", "mgmt.remote_access.source_restricted", True),
    ('set system login message "Authorized access only."\n', "banner.login.present", True),
    ('set system login announcement "Maintenance tonight"\n', "banner.login.present", None),
    ("set protocols lldp interface all\n", "boundary.discovery_protocol.enabled", True),
    ("set protocols lldp disable\n", "boundary.discovery_protocol.enabled", False),
    ("set system radius-server 192.0.2.31 port 1812\n", "auth.central_aaa.enabled", True),
    ("set system authentication-order [ radius password ]\n", "auth.central_aaa.enabled", True),
    ("set system authentication-order password\n", "auth.central_aaa.enabled", None),
    ("set system services ssh authentication-order radius\n", "auth.central_aaa.enabled", None),
    ('set system login user ops authentication encrypted-password "$6$abc$def"\n', "auth.password.storage", "hashed"),
    ('set system login user ops authentication ssh-rsa "ssh-rsa AAAA"\n', "auth.password.storage", None),
    # NX-OS and ASA, from Batfish's configs
    ("username ops password 5 $5$abc role network-admin\n", "auth.password.storage", "type5_md5"),
    ("username ops password 0 <SECRET:password> role network-operator\n", "auth.password.storage", "plaintext"),
    ("username ops role network-operator\n", "auth.password.storage", None),
    ("aaa authentication login default group aaa_server_group1 local\n", "auth.central_aaa.enabled", True),
    ("aaa authentication login error-enable\n", "auth.central_aaa.enabled", None),
    ("line vty\n  access-class VTY_ACL in\n", "mgmt.remote_access.source_restricted", True),
    ("line vty\n  access-class VTY_ACL out\n", "mgmt.remote_access.source_restricted", None),
    ("feature telnet\n", "mgmt.remote_access.protocol_enabled", True),
    ("no feature telnet\n", "mgmt.remote_access.protocol_enabled", False),
    ("no feature lldp\n", "boundary.discovery_protocol.enabled", False),
    ("aaa authentication ssh console authServer LOCAL\n", "auth.central_aaa.enabled", True),
    ("aaa authentication ssh console LOCAL\n", "auth.central_aaa.enabled", False),
    # SNMP communities: the access level is the template's own words
    ("set snmp community public authorization read-only\n", "snmp.community",
     {"name": "public", "permission": "RO", "acl": None}),
    ("snmp-server community NOC-RO group network-operator\n", "snmp.community",
     {"name": "NOC-RO", "permission": "RO", "acl": None}),
    ("snmp-agent community write private\n", "snmp.community", {"name": "private", "permission": "RW", "acl": None}),
    ("set deviceconfig system snmp-setting access-setting version v2c snmp-community-string public\n",
     "snmp.community", {"name": "public", "permission": "RO", "acl": None}),
    # an encrypted community, a read-write one with its ACL beside it, a Junos community without its access
    ("snmp-agent community read cipher %^%#abc\n", "snmp.community", None),
    ("snmp-server community NOC rw NOC-ACL\n", "snmp.community", None),
    ("set snmp community NOC clients 192.0.2.0/24\n", "snmp.community", None),
    # present, but open to every address: not a restriction
    ("set network profiles interface-management-profile MGMT permitted-ip 0.0.0.0/0\n",
     "mgmt.remote_access.source_restricted", False),
    ("set deviceconfig system permitted-ip 0.0.0.0/0\n", "mgmt.remote_access.source_restricted", False),
    # the same words where they configure something else state nothing
    ("set shared server-profile tacplus TAC-MGMT timeout 5\n", "auth.central_aaa.enabled", None),
    ("set network lldp enable yes\n", "boundary.discovery_protocol.enabled", None),
    ("logging host inside\n", "log.remote.destination", None),                  # an interface is not a host
    ("ntp server 192.0.2.10 key 1\n", "time.ntp.authenticated", None),          # a key alone is not authentication
    ("line vty\n exec-timeout 5 0\n", "mgmt.session.idle_timeout", None),       # IOS minutes + seconds: its parser's
    ("router bgp 65000\n  neighbor PG idle-restart-timer 99\n", "mgmt.session.idle_timeout", None),
    ("ip access-list A\n  permit ip 192.0.2.0/24 any\n", "boundary.policy.permit_any", None),
    ("access-list OUTSIDE_IN extended permit ip any host 192.0.2.1\n", "boundary.policy.permit_any", None),
    ("interface Ethernet1\n   ip access-group EDGE-IN in\n", "mgmt.remote_access.source_restricted", None),
    ("ip access-list WAN-IN\n   10 permit ip 192.0.2.0/24 any\n", "boundary.policy.permit_any", None),
    ("access {\n  profile SUBS {\n    authentication-order [ radius password ];\n  }\n}\n",
     "auth.central_aaa.enabled", None),
    ("system {\n  syslog {\n    message \"not a banner\";\n  }\n}\n", "banner.login.present", None),
    ("system {\n  authentication-order [ ldaps password ];\n}\n", "auth.central_aaa.enabled", None),
    # local passwords alone are not centralized AAA, in either form
    ("system {\n  authentication-order password;\n}\n", "auth.central_aaa.enabled", None),
    ("logging buffered 192.0.2.20\n", "log.remote.destination", None),
    ("set telnet enabled\n", "mgmt.remote_access.protocol_enabled", None),
    ("acl number 2000\n rule 5 permit source 192.0.2.0 0.0.0.255\n", "boundary.policy.permit_any", None),
    ("/ip firewall filter\nadd chain=input action=accept protocol=tcp dst-port=22\n", "boundary.policy.permit_any", None),
    ("set access-rule 20 source any destination any service any action drop\n", "boundary.policy.permit_any", None),
])
def test_the_taught_dialect_lines_are_read_and_only_where_they_apply(seeded_adaptive_db, config, predicate, expected):
    values = [f.value for f in _facts(config) if f.predicate == predicate]
    assert values == ([expected] if expected is not None else [])


def test_a_heuristic_that_only_repeats_a_recognizer_does_not_make_the_verdict_provisional(seeded_adaptive_db):
    """The recognizer reads the block header; the lexicon reads the server address inside it.

    Both say centralized AAA is on. Citing the weaker one too would report a confirmed PASS as
    provisional, so a control that is decided stops being decided.
    """
    text = ("system {\n"
            "    authentication-order tacplus;\n"
            "    tacplus-server {\n"
            "        10.10.0.20 secret <SECRET:tacplus>;\n"
            "    }\n"
            "}\n")
    result = _results(text)["MGMT-008"]
    assert (result.status, result.assurance) == (Status.PASS, Assurance.CONFIRMED)


def test_a_heuristic_that_contradicts_a_recognizer_still_speaks(seeded_adaptive_db):
    """A recognizer answers for its setting, but it may never hide a line that disagrees with it."""
    text = ("system {\n"
            "    authentication-order tacplus;\n"
            "}\n"
            "aaa-authentication disable\n")
    facts = [f for f in facts_from_config(_unknown(text)) if f.predicate == "auth.central_aaa.enabled"]
    assert {(f.value, f.assurance) for f in facts} == {
        (True, Assurance.CONFIRMED), (False, Assurance.HEURISTIC)}
    assert _results(text)["MGMT-008"].status != Status.PASS


def test_a_number_that_is_not_a_version_is_not_read_as_one(seeded_adaptive_db):
    # {int} reads a version, so a non-numeric value yields no fact rather than a guess
    facts = _facts("system {\n  services {\n    ssh {\n      protocol-version any;\n    }\n  }\n}\n")
    assert [f for f in facts if f.predicate == SSH_VERSION] == []


# ── 7: secrets ──────────────────────────────────────────────────────────────

def test_no_shipped_recognizer_holds_or_matches_a_secret(seeded_adaptive_db):
    from app.ai.redaction import redact_line
    from app.db.mappings import _holds_secret

    # a password-storage template puts a slot where the secret stands; it never holds a value
    for entry in read_seed_file():
        for text in (entry["command_pattern"], entry.get("scope_template"), entry.get("example_line")):
            assert text is None or not _holds_secret(text), entry

    secrets = (
        "system {\n"
        "  services {\n"
        "    telnet;\n"
        "  }\n"
        "  root-authentication {\n"
        "    encrypted-password \"$6$fake$FakeSeedPassword\";\n"
        "  }\n"
        "  ntp {\n"
        "    authentication-key 7 FakeSeedNtpKey9;\n"
        "  }\n"
        "}\n"
        "snmp-agent community read FakeSeedCommunity\n"
    )
    facts = _facts(secrets)
    secret_lines = {n for n, line in enumerate(secrets.splitlines(), 1)
                    if redact_line(line) != line}
    # the one exception is by design: an SNMP community's line holds the community string, and a seed-only
    # {community} slot reads it at scan time (never stored; every display of it is redacted)
    cited = {n for f in facts if f.predicate != "snmp.community" for n in f.evidence.line_numbers}
    community = {n for f in facts if f.predicate == "snmp.community" for n in f.evidence.line_numbers}
    assert secret_lines and not (cited & secret_lines)
    assert community == {12}


# ── 8–9: nothing else changed ───────────────────────────────────────────────

@pytest.mark.parametrize("name", ["cisco_vulnerable.cfg", "cisco_secure.cfg",
                                  "fortinet_vulnerable.cfg", "fortinet_secure.cfg"])
def test_confirmed_vendor_results_are_identical_with_and_without_seed_knowledge(
        seeded_adaptive_db, name, monkeypatch):
    from app.adaptive.capture import capture_unrecognized_lines
    from app.parsers.detector import identify_vendor

    identification = identify_vendor(_text(FIXTURES / name))
    assert identification.confirmed
    config = identification.config
    capture_unrecognized_lines(config)
    assert config.device.vendor in (Vendor.CISCO_IOS, Vendor.FORTINET)
    seeded = {r.control_id: (r.status, r.assurance) for r in evaluate_controls(config)}

    monkeypatch.setattr(database, "_SEEDED", {seeded_adaptive_db})
    MappingRepository().list_mappings()  # same database, seeds still stored
    assert {r.control_id: (r.status, r.assurance) for r in evaluate_controls(config)} == seeded
    # a confirmed vendor is answered by its parser: no recognizer, seeded or learned, is consulted
    assert all(assurance in (Assurance.PARSER, Assurance.DEFAULT, None)
               for _, assurance in seeded.values())


def test_unknown_vendor_results_only_improve_where_the_seed_covers_the_syntax(seeded_adaptive_db, monkeypatch):
    text = _text(BACKEND.parent / "sample" / "unknown.cfg")
    seeded = _results(text)

    # the synthetic NX-SECURE dialect is not one of the shipped dialects: nothing changes for it
    monkeypatch.setattr(database, "_SEEDED", {seeded_adaptive_db / "unseeded.db"})
    bare_path = seeded_adaptive_db.parent / "unseeded.db"
    monkeypatch.setattr("app.config.settings.adaptive_db_path", bare_path)
    monkeypatch.setattr(database, "_SEEDED", {bare_path})
    bare = _results(text)

    assert {k: (v.status, v.assurance) for k, v in seeded.items()} == \
           {k: (v.status, v.assurance) for k, v in bare.items()}


# ── 10–11: the demo -a fresh deployment, then teaching ─────────────────────

SEEDED_CONTROLS = {"MGMT-001", "MGMT-002", "MGMT-006", "MGMT-009", "LOG-001", "LOG-002"}
NEW_CONCEPTS = {"MGMT-007": "SSH version", "MGMT-003": "management source restriction"}


def _scan(client: TestClient, path: Path) -> dict:
    interpreter = MagicMock(side_effect=AssertionError("AI must not be called"))
    with patch("app.api.routes.scan.interpret_lines", interpreter), \
         patch("app.api.routes.scan.is_available", return_value=False):
        response = client.post("/api/scan",
                               files=[("files", (path.name, _text(path).encode(), "text/plain"))])
    assert response.status_code == 200, response.text
    interpreter.assert_not_called()
    return response.json()


def _result(scan: dict, control_id: str) -> dict:
    return next(r for r in scan["results"] if r["control_id"] == control_id)


def test_a_fresh_deployment_reads_an_unfamiliar_dialect_before_anything_is_taught(seeded_adaptive_db):
    client = TestClient(app)
    scan = _scan(client, DIALECTS / "huawei.conf")
    assert scan["vendor_identification"][0]["status"] != "confirmed"

    decisive = {r["control_id"] for r in scan["results"] if r["assurance"] == "confirmed"}
    assert decisive == SEEDED_CONTROLS
    assert scan["coverage"] > 0

    lines = _text(DIALECTS / "huawei.conf").splitlines()
    for control_id in SEEDED_CONTROLS:
        cited = _result(scan, control_id)["evidence"]["line_numbers"]
        assert cited and all(lines[n - 1].strip() for n in cited)

    # what the seed does not cover is never guessed into a decisive answer
    for control_id in NEW_CONCEPTS:
        result = _result(scan, control_id)
        assert result["assurance"] != "confirmed"
        assert result["status"] in ("unknown", "not_configured") or result["assurance"] == "heuristic"
    # a quoted banner is read: the message being there is the banner
    assert _result(scan, "MGMT-009")["status"] == "pass"


def test_teaching_adds_to_the_seed_knowledge_instead_of_replacing_it(seeded_adaptive_db):
    client = TestClient(app)
    scan = _scan(client, DIALECTS / "huawei.conf")
    scan_id = scan["scan_id"]
    assert _result(scan, "MGMT-007")["assurance"] == "heuristic"

    queue = client.get(f"/api/adaptive/scans/{scan_id}/provisional").json()["items"]
    ssh = next(i for i in queue if i["control_id"] == "MGMT-007")
    line_number = ssh["lines"][0]["line_number"]

    saved = client.post(f"/api/adaptive/scans/{scan_id}/recognizers",
                        json={"control_id": "MGMT-007", "line_number": line_number})
    assert saved.status_code == 200, saved.text
    assert _result(saved.json()["scan"], "MGMT-007")["assurance"] == "confirmed"

    stored = client.get("/api/adaptive/mappings").json()
    assert [m["source"] for m in stored].count(SOURCE_RUNTIME) == 1
    assert [m["source"] for m in stored].count(SOURCE_SEED) == len(read_seed_file())

    # a rescan answers the taught concept and the shipped ones together
    rescan = _scan(client, DIALECTS / "huawei.conf")
    decisive = {r["control_id"] for r in rescan["results"] if r["assurance"] == "confirmed"}
    assert decisive == SEEDED_CONTROLS | {"MGMT-007"}


# ── 12: structured (JSON) configurations ────────────────────────────────────

AWS_SG = json.dumps({"SecurityGroups": [{
    "GroupId": "sg-0abc1234", "GroupName": "web admin",
    "IpPermissions": [
        {"FromPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "ToPort": 22},
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ],
    # the default egress rule allows everything out: it is not an inbound any-any rule
    "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
}]}, indent=2)


def test_a_cloud_security_group_is_read_once_flattened(seeded_adaptive_db):
    scan = _scan(TestClient(app), _json_file(AWS_SG))
    assert _result(scan, "MGMT-003")["status"] == "fail" and _result(scan, "MGMT-003")["assurance"] == "confirmed"
    boundary = _result(scan, "BOUNDARY-001")
    assert boundary["status"] == "fail" and boundary["assurance"] == "confirmed"
    assert boundary["evidence"]["lines"] == ["SecurityGroups IpPermissions IpProtocol -1 IpRanges CidrIp 0.0.0.0/0"]


def test_a_restricted_security_group_passes_and_egress_is_not_a_finding(seeded_adaptive_db):
    data = json.loads(AWS_SG)
    data["SecurityGroups"][0]["IpPermissions"][0]["IpRanges"] = [{"CidrIp": "10.0.0.0/24"}]
    del data["SecurityGroups"][0]["IpPermissions"][1]
    scan = _scan(TestClient(app), _json_file(json.dumps(data)))
    assert _result(scan, "MGMT-003")["status"] == "pass"
    assert _result(scan, "BOUNDARY-001")["status"] != "fail"


def _json_file(text: str) -> Path:
    import tempfile
    path = Path(tempfile.mkdtemp()) / "sg.json"
    path.write_text(text, encoding="utf-8")
    return path


def test_each_snmp_community_is_its_own_finding(seeded_adaptive_db):
    text = "snmp-server community public ro\nsnmp-server community NOC-7f3k ro SNMP-ACL\n"
    communities = [f for f in _facts(text) if f.predicate == "snmp.community"]
    assert sorted(f.value["name"] for f in communities) == ["NOC-7f3k", "public"]
    result = _results(text)["MGMT-004"]
    assert (result.status, result.assurance) == (Status.FAIL, Assurance.CONFIRMED)


def test_a_non_default_read_only_community_passes(seeded_adaptive_db):
    result = _results("set snmp community NOC-7f3k authorization read-only\n")["MGMT-004"]
    assert (result.status, result.assurance) == (Status.PASS, Assurance.CONFIRMED)


def test_snmp_communities_are_read_by_seeds_but_never_taught(seeded_adaptive_db):
    from app.controls.catalog import CONTROLS
    from app.facts.teaching import teachable_predicates
    assert teachable_predicates(CONTROLS["MGMT-004"]) == []


def test_a_security_group_marks_what_it_cannot_have_as_not_applicable(seeded_adaptive_db):
    scan = _scan(TestClient(app), _json_file(AWS_SG))
    for control_id in ("MGMT-006", "MGMT-009", "LOG-002", "AUTH-002"):
        result = _result(scan, control_id)
        assert result["status"] == "n_a" and "security group only filters traffic" in result["reason"]
    # what a security group does express is still judged, on its own lines
    assert _result(scan, "BOUNDARY-001")["status"] == "fail" and _result(scan, "MGMT-003")["status"] == "fail"


PAN_DEMO = (Path(__file__).resolve().parents[2] / "backend" / "tests" / "fixtures" / "demo" / "paloalto_fw_vulnerable.cfg").read_text(encoding="utf-8")


def test_lldp_on_an_interface_an_external_zone_holds_is_decided_and_cites_the_zone(seeded_adaptive_db):
    lldp = _results(PAN_DEMO)["BOUNDARY-003"]
    assert lldp.status == Status.FAIL and lldp.scope == "interface ethernet1/1"
    assert {26, 28} <= set(lldp.evidence.line_numbers)  # the LLDP line and 'set zone untrust … ethernet1/1'
    # the same line on an interface no external zone holds says nothing about exposure
    inside = PAN_DEMO.replace("set zone untrust network layer3 ethernet1/1", "set zone dmz network layer3 ethernet1/1")
    assert _results(inside)["BOUNDARY-003"].status == Status.UNKNOWN


def test_pan_os_password_length_absent_is_decided_from_its_reviewed_factory_default(seeded_adaptive_db):
    length = _results(PAN_DEMO)["AUTH-002"]
    assert length.status == Status.FAIL and "ships with Minimum Password Complexity disabled" in length.reason
    stated = PAN_DEMO + "\nset mgt-config password-complexity enabled yes\nset mgt-config password-complexity minimum-length 12\n"
    assert _results(stated)["AUTH-002"].status == Status.PASS
    # a complexity line the seeds do not read may be stating it: absence then says nothing
    other = PAN_DEMO + "\nset mgt-config password-complexity enabled no\n"
    assert _results(other)["AUTH-002"].status != Status.FAIL
