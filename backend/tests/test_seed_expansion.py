"""
Seed expansion: lockout, password length, SSH and timeout spellings for dialects that already had seeds, and three
families that had none (Dell OS10, VyOS, FortiSwitchOS).

Every new seed is checked three ways: the lines it must read (with the value it must read), the near-miss lines it
must not read, and whole configurations whose decided verdicts are written down here. Sources for every spelling are
listed in docs/seed-knowledge.md.
"""

import json
import sqlite3
from pathlib import Path

import pytest

from app.ai.redaction import redact_line
from app.controls.evaluate import evaluate_controls
from app.db import database
from app.facts.recognizers import recognizer_facts
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Status

BACKEND = Path(__file__).resolve().parents[1]
DIALECTS = BACKEND / "tests" / "fixtures" / "seed_dialects"
LOOKALIKES = BACKEND / "tests" / "fixtures" / "lookalikes"
DECISIVE = {Assurance.PARSER, Assurance.CONFIRMED, Assurance.DEFAULT}


def _values(text: str, predicate: str, subject=None) -> list:
    return [f.value for f in recognizer_facts(text.splitlines())[0]
            if f.predicate == predicate and (subject is None or f.subject == subject)]


def _decided(path: Path) -> dict:
    """control id -> 'pass' / 'fail' for every decided result of an unconfirmed configuration."""
    text = path.read_text(encoding="utf-8")
    config = NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN), raw_config=text, raw_lines=text.splitlines())
    out = {}
    for r in evaluate_controls(config):
        if r.status in (Status.PASS, Status.FAIL) and r.assurance in DECISIVE:
            out[r.control_id] = "fail" if r.status == Status.FAIL or out.get(r.control_id) == "fail" else "pass"
    return out


# ── every new seed: what it reads, and what it must not ────────────────────────

@pytest.mark.parametrize("text, predicate, subject, expected", [
    ('ssh version 2', 'mgmt.ssh.version', None, 2),
    ('ssh version 1', 'mgmt.ssh.version', None, 1),
    ('ip ssh version 2', 'mgmt.ssh.version', None, 2),
    ('ssh timeout 5', 'mgmt.session.idle_timeout', None, 5.0),
    ('ssh timeout 60', 'mgmt.session.idle_timeout', None, 60.0),
    ('ip ssh time-out 60', 'mgmt.session.idle_timeout', None, None),
    ('console timeout 0', 'mgmt.session.idle_timeout', None, 0.0),
    ('http server idle-timeout 20', 'mgmt.session.idle_timeout', None, 20.0),
    ('http server session-timeout 20', 'mgmt.session.idle_timeout', None, None),
    ('aaa local authentication attempts max-fail 3', 'auth.login.max_attempts', None, 3),
    ('password-policy minimum-length 15', 'auth.password.min_length', None, 15),
    ('password-policy minimum-uppercase 1', 'auth.password.min_length', None, None),
    ('set deviceconfig setting management admin-lockout failed-attempts 5', 'auth.login.max_attempts', None, 5),
    ('set deviceconfig setting management admin-lockout failed-attempts 0', 'auth.login.max_attempts', None, 0),
    ('set deviceconfig setting management admin-lockout lockout-time 30', 'auth.login.max_attempts', None, None),
    ('set password-controls min-password-length 8', 'auth.password.min_length', None, 8),
    ('set password-controls password-history-length 10', 'auth.password.min_length', None, None),
    ('userpassphrase min-length 16', 'auth.password.min_length', None, 16),
    ('userpassphrase max-length 127', 'auth.password.min_length', None, None),
    ('ssh login-attempts 3', 'auth.login.max_attempts', None, 3),
    ('aaa authentication policy lockout failure 3', 'auth.login.max_attempts', None, 3),
    ('aaa authentication policy lockout failure 5 duration 900', 'auth.login.max_attempts', None, 5),
    ('management security\n   password minimum length 15', 'auth.password.min_length', None, 15),
    ('password minimum length 15', 'auth.password.min_length', None, None),
    ('ntp authenticate servers', 'time.ntp.authenticated', None, True),
    ('no ntp authenticate servers', 'time.ntp.authenticated', None, False),
    ('ntp authenticate', 'time.ntp.authenticated', None, True),
    ('ip telnet server enable', 'mgmt.remote_access.protocol_enabled', 'telnet', True),
    ('no ip telnet server enable', 'mgmt.remote_access.protocol_enabled', 'telnet', False),
    ('password-attributes min-length 6', 'auth.password.min_length', None, 6),
    ('password-attributes max-retry 5 lockout-period 15', 'auth.login.max_attempts', None, 5),
    ('password-attributes max-retry 3', 'auth.login.max_attempts', None, 3),
    ('password-attributes lockout-period 15', 'auth.login.max_attempts', None, None),
    ('password-attributes character-restriction upper 1', 'auth.password.min_length', None, None),
    ('username admin password $6$q9QBeYjZ$jfxzVqGh role sysadmin priv-lvl 15', 'auth.account.name', None, 'admin'),
    ('username netops password $6$q9QBeYjZ$jfxzVqGh role sysadmin', 'auth.account.name', None, None),
    ('banner login ^C', 'banner.login.present', None, True),
    ('banner login', 'banner.login.present', None, True),
    ('no banner login', 'banner.login.present', None, False),
    ('banner exec ^C', 'banner.login.present', None, None),
    ("set system login banner pre-login 'Authorized access only.'", 'banner.login.present', None, True),
    ("set system login banner post-login 'Welcome to VyOS'", 'banner.login.present', None, None),
    ("set system login radius-server 192.0.2.60 port '1812'", 'auth.central_aaa.enabled', None, True),
    ("set system login radius-server 192.0.2.60 secret 's3cr3t'", 'auth.central_aaa.enabled', None, True),
    ("set service snmp community public authorization 'ro'", 'snmp.community', None, {'name': 'public', 'permission': 'RO', 'acl': None}),
    ('set service snmp community public authorization rw', 'snmp.community', None, None),
    ("set service ssh ciphers '3des-cbc'", 'mgmt.crypto.weak_allowed', None, True),
    ("set service ssh ciphers 'aes256-ctr'", 'mgmt.crypto.weak_allowed', None, False),
    ("set service ssh ciphers 'chacha20-poly1305@openssh.com'", 'mgmt.crypto.weak_allowed', None, None),
    ("set service ssh macs 'hmac-md5'", 'mgmt.crypto.weak_allowed', None, True),
    ("set service ssh macs 'hmac-sha1'", 'mgmt.crypto.weak_allowed', None, None),
    ("set system login user vyos authentication encrypted-password '$6$Qd9pLk2m$Yb7wN1c4'", 'auth.account.name', None, 'vyos'),
    ("set system login user netops authentication encrypted-password '$6$Qd9pLk2m$Yb7wN1c4'", 'auth.account.name', None, None),
    ("set service ssh port '22'", 'mgmt.crypto.weak_allowed', None, None),
    ('config system global\n    set admintimeout 5\nend', 'mgmt.session.idle_timeout', None, 5.0),
    ('config system global\n    set admintimeout 480\nend', 'mgmt.session.idle_timeout', None, 480.0),
    ('config system admin\n    edit admin\n        set admintimeout 5\n    next\nend', 'mgmt.session.idle_timeout', None, None),
    ('config system global\n    set admin-lockout-threshold 3\nend', 'auth.login.max_attempts', None, 3),
    ('config system global\n    set strong-crypto disable\nend', 'mgmt.crypto.weak_allowed', None, True),
    ('config system global\n    set strong-crypto enable\nend', 'mgmt.crypto.weak_allowed', None, False),
    ('set admintimeout 5', 'mgmt.session.idle_timeout', None, None),
])
def test_each_new_seed_reads_its_line_and_nothing_near_it(seeded_adaptive_db, text, predicate, subject, expected):
    assert _values(text, predicate, subject) == ([] if expected is None else [expected])


# ── whole configurations ───────────────────────────────────────────────────────

@pytest.mark.parametrize("name, expected", [
    ("dell_os10_insecure.conf", {"MGMT-001": "fail", "MGMT-004": "fail", "MGMT-011": "fail", "MGMT-009": "fail",
                                 "AUTH-001": "fail", "AUTH-002": "fail", "AUTH-003": "fail", "LOG-001": "pass"}),
    ("dell_os10_secure.conf", {"MGMT-001": "pass", "MGMT-008": "pass", "MGMT-009": "pass", "AUTH-001": "pass",
                               "AUTH-002": "pass", "LOG-001": "pass", "LOG-002": "pass"}),
    ("vyos_insecure.conf", {"MGMT-004": "fail", "MGMT-011": "fail", "MGMT-008": "fail", "MGMT-009": "fail",
                            "AUTH-003": "fail", "CRYPTO-002": "fail",
                            # 'set system syslog global …' names syslog, so its absence is never asserted
                            "LOG-001": None}),
    ("vyos_secure.conf", {"MGMT-008": "pass", "MGMT-009": "pass", "LOG-001": "pass", "CRYPTO-002": "pass"}),
])
def test_new_dialects_are_decided_from_shipped_knowledge(seeded_adaptive_db, name, expected):
    decided = _decided(DIALECTS / name)
    assert {k: decided.get(k) for k in expected} == expected


@pytest.mark.parametrize("name", ["dell_os10_insecure.conf", "dell_os10_secure.conf", "vyos_insecure.conf",
                                  "vyos_secure.conf"])
def test_every_new_dialect_contributes_decisive_cited_facts(seeded_adaptive_db, name):
    facts = recognizer_facts((DIALECTS / name).read_text(encoding="utf-8").splitlines())[0]
    assert len(facts) >= 3
    assert all(f.assurance == Assurance.CONFIRMED for f in facts)
    assert all(f.evidence.line_numbers for f in facts if f.value is not None)


def test_a_fortiswitch_is_unverified_yet_its_global_settings_are_read(seeded_adaptive_db):
    decided = _decided(LOOKALIKES / "fortiswitch.cfg")
    assert decided.get("MGMT-006") == "pass"  # set admintimeout 5 under config system global


def test_cisco_asa_management_settings_are_decided(seeded_adaptive_db):
    decided = _decided(LOOKALIKES / "cisco_asa.cfg")
    assert decided.get("MGMT-007") == "pass"  # ssh version 2
    assert decided.get("MGMT-006") == "pass"  # ssh timeout 5


# ── the false alarm this branch fixes ──────────────────────────────────────────

def test_asa_http_server_for_asdm_is_not_a_decided_cleartext_http_failure(seeded_adaptive_db):
    """ASA 'http server enable' starts ASDM, which is HTTPS. Huawei writes the same words for HTTP, so its seeds
    only read configurations that look like Huawei VRP."""
    assert "MGMT-002" not in _decided(LOOKALIKES / "cisco_asa.cfg")


def test_huawei_http_management_is_still_read(seeded_adaptive_db):
    assert _decided(DIALECTS / "huawei.conf").get("MGMT-002") == "fail"


def test_existing_databases_get_the_seed_corrections_by_migration(seeded_adaptive_db):
    """The seed loader never rewrites a stored row, so a database that already held the old rows is fixed by a
    migration. Taught rows are never touched."""
    db = seeded_adaptive_db
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE learned_mappings SET dialect_fingerprint = NULL WHERE vendor = 'Huawei VRP'")
        conn.execute("UPDATE learned_mappings SET vendor = 'Juniper Junos' WHERE vendor = 'Juniper Junos / VyOS'")
        conn.execute("INSERT INTO learned_mappings (concept, normalized_field, vendor, command_pattern, extraction_method,"
                     " expected_value_type, confirmed, active, created_at, updated_at, predicate, subject, source)"
                     " VALUES ('x', '', 'Huawei VRP', 'http server {polarity}', 'recognizer', 'boolean', 1, 0, 'now',"
                     " 'now', 'mgmt.remote_access.protocol_enabled', 'http', 'runtime')")
        conn.execute("PRAGMA user_version = 6")
    database.init_db(db)
    with sqlite3.connect(db) as conn:
        rows = conn.execute("SELECT source, dialect_fingerprint FROM learned_mappings WHERE vendor = 'Huawei VRP'"
                            " AND command_pattern IN ('http server {polarity}', '{neg} http server enable')").fetchall()
        relabelled = conn.execute("SELECT COUNT(*) FROM learned_mappings WHERE vendor = 'Juniper Junos / VyOS'"
                                  " AND source = 'seed'").fetchone()[0]
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == 7
    assert sorted(fp is not None for source, fp in rows if source == "seed") == [True, True]
    assert [fp for source, fp in rows if source == "runtime"] == [None]
    assert relabelled == 2


# ── the small engine changes the seeds needed ──────────────────────────────────

def test_a_password_policy_line_is_not_redacted_as_a_password():
    assert redact_line("password minimum length 15") == "password minimum length 15"
    assert redact_line("enable password 7 0822455D0A16") == "enable password 7 <SECRET:type7>"
    assert "s3cr3t" not in redact_line("username admin password 0 s3cr3t")


def test_a_quoted_value_is_read_like_an_unquoted_one(seeded_adaptive_db):
    assert _values("set service ssh ciphers '3des-cbc'", "mgmt.crypto.weak_allowed") == [True]
    assert _values("set service ssh ciphers 3des-cbc", "mgmt.crypto.weak_allowed") == [True]
    # a quote is punctuation around a value, never half of one
    assert _values("set service ssh ciphers '3des-cbc", "mgmt.crypto.weak_allowed") == [True]


def test_the_shipped_seeds_all_load(seeded_adaptive_db):
    from app.db.mappings import MappingRepository
    from app.facts.seed import read_seed_file

    assert len(MappingRepository().list_mappings()) == len(read_seed_file()) == 386
