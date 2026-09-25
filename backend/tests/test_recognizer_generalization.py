"""
Recognizers generalize: a concept is taught once and read again in its variants.

    teach N concepts → a configuration writes them with other addresses, names, numbers, indentation
    and block placement → those lines are recognized with no second Teach → only genuinely new
    concepts stay in the resolution queue

Every recognizer here is still decisive, so the negatives matter as much as the positives: the same
leaf word in another block, a value the slot cannot read and a half-stated multi-fact control must
all leave the control undecided rather than guess.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.adaptive.matcher import EXTRACTION_RECOGNIZER
from app.controls.catalog import CONTROLS
from app.controls.evaluate import evaluate_controls
from app.db.mappings import LearnedMapping, MappingRepository, MappingValidationError
from app.facts.predicates import (
    IDLE_TIMEOUT, LOG_REMOTE_DESTINATION, NTP_AUTHENTICATED, NTP_SERVER, PROTOCOL_ENABLED, SSH_VERSION,
)
from app.facts.recognizers import draft_recognizer, recognizer_facts
from app.facts.teaching import asserted_candidate
from app.main import app
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Status

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ── teaching a concept, the way the Teach page does ─────────────────────────

def teach(text: str, control_id: str, line_number: int, predicate: str, value=None,
          command_pattern: str | None = None) -> LearnedMapping:
    """Draft a recognizer from one line of ``text`` and store it. Raises like the API does."""
    lines = text.splitlines()
    control = CONTROLS[control_id]
    candidate = asserted_candidate(lines, control, line_number, predicate, value)
    draft = draft_recognizer(lines, control.needs, line_number, asserted=candidate)
    return MappingRepository().save_mapping(LearnedMapping(
        concept=control_id, normalized_field="", extraction_method=EXTRACTION_RECOGNIZER, confirmed=True,
        command_pattern=command_pattern or draft["command_pattern"], constant_value=draft["constant_value"],
        predicate=draft["predicate"], subject=draft["subject"], scope_template=draft["scope_template"],
        example_line=draft["example_line"]))


def read(text: str, predicate: str, subject: str | None = None):
    """The value the stored recognizers read for a predicate, or ``NOTHING`` when none does."""
    facts, _ = recognizer_facts(text.splitlines())
    for fact in facts:
        if fact.predicate == predicate and (subject is None or fact.subject == subject):
            return fact.value
    return NOTHING


NOTHING = "no fact"


def _config(text: str) -> NormalizedConfig:
    return NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="g"),
                            raw_config=text, raw_lines=text.splitlines())


def outcome(text: str, control_id: str):
    return next(r for r in evaluate_controls(_config(text)) if r.control_id == control_id)


# ── 1. one recognizer, many values ──────────────────────────────────────────

NTP_TAUGHT = "hostname EDGE-1\nntp server 10.0.50.10\n"


@pytest.mark.parametrize("line, expected", [
    ("ntp server 203.0.113.9", ["203.0.113.9"]),                 # another address
    ("ntp server 2001:db8::10", ["2001:db8::10"]),               # IPv6
    ("ntp server ntp1.example.com", ["ntp1.example.com"]),       # an FQDN
    ("ntp server timehost", ["timehost"]),                       # a bare hostname
    ("ntp server 198.51.100.7", ["198.51.100.7"]),
])
def test_one_taught_concept_reads_every_kind_of_destination(line, expected):
    teach(NTP_TAUGHT, "LOG-002", 2, NTP_SERVER)
    assert read(f"hostname OTHER-99\n{line}\n", NTP_SERVER) == expected


@pytest.mark.parametrize("line", [
    "ntp server enable",     # a polarity word names no host
    "ntp server 2",          # nor does a bare number
])
def test_a_destination_slot_refuses_what_is_not_a_destination(line):
    teach(NTP_TAUGHT, "LOG-002", 2, NTP_SERVER)
    assert read(f"hostname X\n{line}\n", NTP_SERVER) is NOTHING


# ── 2. layout does not matter ───────────────────────────────────────────────

JUNOS_NTP = "system {\n    ntp {\n        server 10.0.50.10;\n    }\n}\n"


@pytest.mark.parametrize("text, expected", [
    ("system {\n    ntp {\n        server 203.0.113.1;\n    }\n}\n", ["203.0.113.1"]),
    ("system {\n\tntp {\n\t\tserver 203.0.113.2;\n\t}\n}\n", ["203.0.113.2"]),            # tabs
    ("system {\n      ntp {\n                server 203.0.113.3;\n      }\n}\n", ["203.0.113.3"]),
    ("system {\n  ntp {\n    server    203.0.113.4;\n  }\n}\n", ["203.0.113.4"]),         # inner spacing
    # statement order inside the block, and the block's placement among its siblings
    ("system {\n  ntp {\n    boot-server 10.9.9.9;\n    server 203.0.113.5;\n  }\n}\n", ["203.0.113.5"]),
    ("system {\n  syslog {\n    host 10.8.8.8;\n  }\n  ntp {\n    server 203.0.113.6;\n  }\n}\n",
     ["203.0.113.6"]),
])
def test_indentation_whitespace_and_statement_order_do_not_matter(text, expected):
    teach(JUNOS_NTP, "LOG-002", 3, NTP_SERVER)
    assert read(text, NTP_SERVER) == expected


# ── 3. positive and negative forms of one concept stay opposite ─────────────

@pytest.mark.parametrize("taught, line, asserted, positive, negative", [
    # a leading negator: one recognizer, both polarities
    ("hostname A\nno telnet server\n", 2, False,
     "hostname Z\ntelnet server\n", "hostname Z\nno telnet server\n"),
    ("hostname A\nno management telnet\n", 2, False,
     "hostname Z\nmanagement telnet\n", "hostname Z\nno management telnet\n"),
    # taught from the enabled form instead: the same one recognizer, the same two readings
    ("hostname A\ntelnet server\n", 2, True,
     "hostname Z\ntelnet server\n", "hostname Z\nno telnet server\n"),
    # a bare statement inside the block that gives it its meaning
    ("system {\n  services {\n    telnet;\n  }\n}\n", 3, True,
     "system {\n  services {\n    telnet;\n  }\n}\n", "system {\n  services {\n    no telnet;\n  }\n}\n"),
])
def test_a_positive_and_a_negative_form_read_as_opposites(taught, line, asserted, positive, negative):
    teach(taught, "MGMT-001", line, PROTOCOL_ENABLED, value=asserted)
    assert read(positive, PROTOCOL_ENABLED, "telnet") is True
    assert read(negative, PROTOCOL_ENABLED, "telnet") is False


def test_disabled_shutdown_and_absent_stay_distinct(seeded_adaptive_db):
    """Three different configurations, three different answers -none of them a guess."""
    assert read("telnet server enable\n", PROTOCOL_ENABLED, "telnet") is True
    assert read("telnet server disable\n", PROTOCOL_ENABLED, "telnet") is False
    assert read("undo telnet server enable\n", PROTOCOL_ENABLED, "telnet") is False
    assert read("hostname ONLY\n", PROTOCOL_ENABLED, "telnet") is NOTHING


def test_an_ambiguous_line_yields_no_fact():
    """``shutdown`` under a service block says nothing the recognizer was taught to read."""
    teach("hostname A\nno telnet server\n", "MGMT-001", 2, PROTOCOL_ENABLED, value=False)
    assert read("hostname A\ntelnet server shutdown\n", PROTOCOL_ENABLED, "telnet") is NOTHING


# ── 4. near-miss negatives: the same leaf word elsewhere ────────────────────

@pytest.mark.parametrize("text", [
    # the leaf word in a block that is not the one it was taught in
    "system {\n  syslog {\n    server 203.0.113.9;\n  }\n}\n",
    "firewall {\n  filter BLOCK {\n    server 203.0.113.9;\n  }\n}\n",
    "system {\n  services {\n    dhcp {\n      server 203.0.113.9;\n    }\n  }\n}\n",
    # the taught block is only an ancestor, not the block the statement is in
    "ntp {\n  traceoptions {\n    server 203.0.113.9;\n  }\n}\n",
])
def test_the_same_leaf_word_in_another_block_does_not_match(text):
    teach(JUNOS_NTP, "LOG-002", 3, NTP_SERVER)
    assert read(text, NTP_SERVER) is NOTHING


@pytest.mark.parametrize("text", [
    "hostname X\nmanagement telnet\n   idle-timeout 600\n",       # another management block
    "hostname X\nmanagement api http-commands\n   idle-timeout 600\n",
])
def test_a_scoped_value_recognizer_answers_only_its_own_block(text):
    teach("hostname X\nmanagement ssh\n   idle-timeout 900\n", "MGMT-006", 3, IDLE_TIMEOUT,
          command_pattern="idle-timeout {duration:s}")
    assert read(text, IDLE_TIMEOUT) is NOTHING


def test_a_traffic_rule_naming_telnet_is_not_management_access(seeded_adaptive_db):
    assert read("set rulebase security rules Block-Telnet application telnet action deny\n",
                PROTOCOL_ENABLED, "telnet") is NOTHING


# ── 5. value-sensitive concepts: same recognizer, different control ─────────

TIMEOUT_TAUGHT = "hostname A\nset ssh server session-timeout 600\n"


@pytest.mark.parametrize("seconds, status", [
    (0, Status.FAIL),        # a disabled timeout
    (300, Status.PASS),      # 5 minutes
    (900, Status.PASS),      # 15 minutes, the limit
    (1800, Status.FAIL),     # 30 minutes, too long
])
def test_one_timeout_recognizer_gives_different_control_results(seconds, status):
    teach(TIMEOUT_TAUGHT, "MGMT-006", 2, IDLE_TIMEOUT, command_pattern="set ssh server session-timeout {duration:s}")
    text = f"hostname B\nset ssh server session-timeout {seconds}\n"
    assert read(text, IDLE_TIMEOUT) == seconds / 60
    result = outcome(text, "MGMT-006")
    assert (result.status, result.assurance) == (status, Assurance.CONFIRMED)


@pytest.mark.parametrize("version, status", [(1, Status.FAIL), (2, Status.PASS)])
def test_one_ssh_recognizer_gives_different_control_results(version, status):
    teach("hostname A\nip ssh version 2\n", "MGMT-007", 2, SSH_VERSION)
    text = f"hostname B\nip ssh version {version}\n"
    assert read(text, SSH_VERSION) == version
    assert outcome(text, "MGMT-007").status is status


def test_a_version_the_slot_cannot_read_leaves_the_control_undecided():
    teach("hostname A\nip ssh version 2\n", "MGMT-007", 2, SSH_VERSION)
    assert read("hostname B\nip ssh version any\n", SSH_VERSION) is NOTHING


# ── 6. multi-fact controls: one atomic predicate each, the control composes ─

def test_a_lone_ntp_server_never_yields_authenticated_ntp():
    teach(NTP_TAUGHT, "LOG-002", 2, NTP_SERVER)
    text = "hostname B\nntp server 203.0.113.1\n"
    assert read(text, NTP_SERVER) == ["203.0.113.1"]
    assert read(text, NTP_AUTHENTICATED) is NOTHING
    # LOG-002 needs both facts; with only half of them it must not decide
    assert outcome(text, "LOG-002").status is Status.UNKNOWN


def test_the_second_fact_decides_the_control():
    teach(NTP_TAUGHT, "LOG-002", 2, NTP_SERVER)
    teach("hostname A\nntp authentication enable\n", "LOG-002", 2, NTP_AUTHENTICATED, value=True)
    assert outcome("hostname B\nntp server 203.0.113.1\nntp authentication enable\n",
                   "LOG-002").status is Status.PASS
    assert outcome("hostname B\nntp server 203.0.113.1\nntp authentication disable\n",
                   "LOG-002").status is Status.FAIL


def test_a_recognizer_cannot_be_taught_a_setting_its_line_does_not_state():
    """``ntp server <address>`` names a server and says nothing about authenticating it."""
    with pytest.raises((MappingValidationError, ValueError)):
        teach(NTP_TAUGHT, "LOG-002", 2, NTP_AUTHENTICATED, value=True)
    assert read("hostname B\nntp server 203.0.113.1\n", NTP_AUTHENTICATED) is NOTHING


# ── 7. a taught concept is reused, with no second Teach ─────────────────────

def test_a_taught_concept_is_reused_on_a_configuration_it_was_never_taught_on():
    teach(NTP_TAUGHT, "LOG-002", 2, NTP_SERVER)
    teach("hostname A\nno telnet server\n", "MGMT-001", 2, PROTOCOL_ENABLED, value=False)

    other = ("hostname BRANCH-42\n"
             "no telnet server\n"
             "ntp server ntp.pool.example.com\n")
    facts, skip = recognizer_facts(other.splitlines())
    assert {f.predicate for f in facts} == {PROTOCOL_ENABLED, NTP_SERVER}
    assert all(f.assurance is Assurance.CONFIRMED for f in facts)
    assert skip >= {2, 3}  # both lines are answered; no heuristic and no AI is asked about them


# ── 8. acceptance: teach five concepts through the API, scan seven variants ─

# A dialect no shipped seed reads, so every fact below comes from what is taught here.
TEACH_SOURCE = """device-name EDGE-TEACH
no remote-shell telnet service
secure-shell protocol-level 2
time-source peer 10.0.50.10
time-source integrity enabled
console-session inactivity-limit 600
"""

# control → (line of TEACH_SOURCE, predicate, asserted value, the pattern the admin confirms)
LESSONS = [
    ("MGMT-001", 2, PROTOCOL_ENABLED, False, None),
    ("MGMT-007", 3, SSH_VERSION, None, None),
    ("LOG-002", 4, NTP_SERVER, None, None),
    ("LOG-002", 5, NTP_AUTHENTICATED, True, None),
    ("MGMT-006", 6, IDLE_TIMEOUT, None, "console-session inactivity-limit {duration:s}"),
]
TAUGHT_CONTROLS = {control_id for control_id, *_ in LESSONS}

# The same dialect written by another team: other names, addresses, numbers, indentation and order,
# plus one line stating a concept nothing has been taught about.
VARIANTS = """device-name BRANCH-77
   no remote-shell telnet service
time-source integrity disabled
secure-shell protocol-level 1
time-source peer ntp1.example.com
time-source peer 2001:db8::25
console-session inactivity-limit 2400
legal-notice text "AUTHORIZED USE ONLY"
"""
VARIANT_LINES = 7  # lines 2-8: six variants of a taught concept, one genuinely new


def _scan(client: TestClient, name: str, text: str) -> dict:
    response = client.post("/api/scan", files={"files": (name, io.BytesIO(text.encode()), "text/plain")})
    assert response.status_code == 200, response.text
    return response.json()


def _teach_through_the_api(client: TestClient, scan_id: str) -> None:
    for control_id, line_number, predicate, value, pattern in LESSONS:
        body = {"config_index": 0, "control_id": control_id, "line_number": line_number,
                "predicate": predicate, "asserted_value": value}
        if pattern:
            body["command_pattern"] = pattern
        saved = client.post(f"/api/adaptive/scans/{scan_id}/recognizers", json=body)
        assert saved.status_code == 200, f"{control_id} line {line_number}: {saved.text}"


@pytest.fixture
def taught(seeded_adaptive_db):
    """A fresh deployment that has been taught the five concepts of ``TEACH_SOURCE``."""
    client = TestClient(app)
    _teach_through_the_api(client, _scan(client, "teach-src.conf", TEACH_SOURCE)["scan_id"])
    return client


def test_a_scan_of_seven_variant_lines_needs_no_further_teaching(taught):
    scan = _scan(taught, "branch77.conf", VARIANTS)

    decided = {r["control_id"] for r in scan["results"] if r["assurance"] == "confirmed"}
    assert TAUGHT_CONTROLS <= decided, f"a taught concept was not reused: {TAUGHT_CONTROLS - decided}"

    queue = taught.get(f"/api/adaptive/scans/{scan['scan_id']}/unresolved").json()
    unresolved = {item["control_id"] for item in queue["items"]}
    assert unresolved & TAUGHT_CONTROLS == set(), f"still being asked about: {unresolved & TAUGHT_CONTROLS}"
    # what is left is genuinely new -the banner line is offered, and nothing reads it yet
    assert "MGMT-009" in unresolved
    banner = next(i for i in queue["items"] if i["control_id"] == "MGMT-009")
    assert 8 in [line["line_number"] for line in banner["suggested_lines"]]

    lines = VARIANTS.splitlines()
    cited = {n for r in scan["results"] if r["assurance"] == "confirmed" for n in r["evidence"]["line_numbers"]}
    assert cited == set(range(2, 2 + VARIANT_LINES - 1))     # every taught line, and only those
    assert all(lines[n - 1].strip() for n in cited)


def test_the_variant_values_are_the_new_file_s_own(taught):
    """Same recognizers, different file: the values and the verdicts are this configuration's."""
    assert read(VARIANTS, PROTOCOL_ENABLED, "telnet") is False
    assert read(VARIANTS, SSH_VERSION) == 1
    assert set(read(VARIANTS, NTP_SERVER)) == {"ntp1.example.com", "2001:db8::25"}
    assert read(VARIANTS, NTP_AUTHENTICATED) is False
    assert read(VARIANTS, IDLE_TIMEOUT) == 40.0
    assert read(VARIANTS, LOG_REMOTE_DESTINATION) is NOTHING

    assert outcome(TEACH_SOURCE, "MGMT-007").status is Status.PASS     # version 2
    assert outcome(VARIANTS, "MGMT-007").status is Status.FAIL         # version 1
    assert outcome(TEACH_SOURCE, "MGMT-006").status is Status.PASS     # 10 minutes
    assert outcome(VARIANTS, "MGMT-006").status is Status.FAIL         # 40 minutes
    assert outcome(TEACH_SOURCE, "LOG-002").status is Status.PASS      # a server and authentication
    assert outcome(VARIANTS, "LOG-002").status is Status.FAIL          # servers, authentication off


def test_nothing_is_taught_twice(taught):
    """Two more scans of the same dialect add no recognizer and ask for none."""
    before = len(MappingRepository().list_mappings())
    _scan(taught, "a.conf", VARIANTS)
    _scan(taught, "b.conf", VARIANTS.replace("ntp1.example.com", "ntp9.example.org"))
    assert len(MappingRepository().list_mappings()) == before


def test_a_concept_the_seed_already_ships_is_refused_as_a_duplicate(seeded_adaptive_db):
    """`no telnet server` is shipped knowledge: teaching it again conflicts instead of duplicating."""
    from app.db.mappings import MappingConflictError

    with pytest.raises(MappingConflictError):
        teach("hostname A\nno telnet server\n", "MGMT-001", 2, PROTOCOL_ENABLED, value=False)


# ── 9. nothing else moved ───────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["cisco_vulnerable.cfg", "cisco_secure.cfg",
                                  "fortinet_vulnerable.cfg", "fortinet_secure.cfg"])
def test_a_confirmed_vendor_is_still_answered_by_its_parser(seeded_adaptive_db, name):
    from app.parsers.detector import identify_vendor

    identification = identify_vendor((FIXTURES / name).read_text(encoding="utf-8"))
    assert identification.confirmed
    results = evaluate_controls(identification.config)
    assert all(r.assurance in (Assurance.PARSER, Assurance.DEFAULT, None) for r in results)


def test_no_shipped_or_taught_recognizer_stores_a_secret(taught):
    from app.db.mappings import _refuse_secrets

    stored = MappingRepository().list_mappings()
    assert len(stored) > len(LESSONS)
    # a slot may stand where a secret would (``secret {enum:type} {any}``); a value never does
    for mapping in stored:
        _refuse_secrets(mapping)


# ── 10. settings a configuration states by naming a thing ──────────────────

PERMITTED_IP = "set deviceconfig system hostname PA-1\nset deviceconfig system permitted-ip 10.10.10.0/24\n"
SOURCE_RESTRICTED = "mgmt.remote_access.source_restricted"
CENTRAL_AAA = "auth.central_aaa.enabled"


def test_a_source_restriction_is_taught_from_the_address_it_names():
    """No dialect writes "source restriction: on" -it names an allowed source, and that is the setting."""
    saved = teach(PERMITTED_IP, "MGMT-003", 2, SOURCE_RESTRICTED, value=True)
    # the address is which source is permitted, not whether the setting is on: it must not be memorized
    assert "10.10.10.0/24" not in saved.command_pattern
    assert saved.command_pattern == "{neg} set deviceconfig system permitted-ip {any}"


@pytest.mark.parametrize("line", [
    "set deviceconfig system permitted-ip 192.0.2.0/24",
    "set deviceconfig system permitted-ip 203.0.113.7",
    "set deviceconfig system permitted-ip 2001:db8::/32",
])
def test_the_taught_restriction_reads_any_other_source(line):
    teach(PERMITTED_IP, "MGMT-003", 2, SOURCE_RESTRICTED, value=True)
    text = f"set deviceconfig system hostname PA-9\n{line}\n"
    assert read(text, SOURCE_RESTRICTED) is True
    assert outcome(text, "MGMT-003").status is Status.PASS


@pytest.mark.parametrize("line", [
    "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 192.0.2.10",
    "set deviceconfig system syslog-service server 192.0.2.20",
    "set deviceconfig system ip-address 203.0.113.10",
])
def test_another_line_carrying_an_address_is_not_a_source_restriction(line):
    teach(PERMITTED_IP, "MGMT-003", 2, SOURCE_RESTRICTED, value=True)
    assert read(f"set deviceconfig system hostname PA-9\n{line}\n", SOURCE_RESTRICTED) is NOTHING


def test_naming_an_aaa_server_teaches_central_aaa():
    saved = teach("hostname A\nradius-server host 10.0.50.10\n", "MGMT-008", 2, CENTRAL_AAA, value=True)
    assert "10.0.50.10" not in saved.command_pattern
    assert read("hostname B\nradius-server host 198.51.100.4\n", CENTRAL_AAA) is True
    assert outcome("hostname B\nradius-server host 198.51.100.4\n", "MGMT-008").status is Status.PASS


@pytest.mark.parametrize("control_id, predicate, taught, line", [
    # a toggle: the line states a value for another setting and only mentions this one
    ("LOG-002", NTP_AUTHENTICATED, "system {\n  ntp {\n    server 192.168.10.10;\n  }\n}\n", 3),
    ("MGMT-001", PROTOCOL_ENABLED, "hostname A\nntp server 10.0.50.10\n", 2),
    ("BOUNDARY-002", "boundary.source_routing.enabled", "hostname A\nip route 10.0.0.0 255.0.0.0 10.0.0.1\n", 2),
])
def test_a_toggle_still_cannot_be_taught_from_a_line_that_only_mentions_it(control_id, predicate, taught, line):
    with pytest.raises((MappingValidationError, ValueError)):
        teach(taught, control_id, line, predicate, value=True)


def test_the_gate_holds_for_a_hand_written_template_too():
    """Drafting is not the gate: typing the template by hand must not get past the same rule."""
    with pytest.raises(MappingValidationError):
        MappingRepository().save_mapping(LearnedMapping(
            concept="sneaky", normalized_field="", extraction_method=EXTRACTION_RECOGNIZER, confirmed=True,
            command_pattern="{neg} ntp server {any}", predicate=NTP_AUTHENTICATED,
            example_line="ntp server 192.168.10.10"))


# A line that states nothing of its own is evidence only because it is there, so it has to be a line
# about the setting. These are lines the Teach page used to accept for any check at all.
NOISE = ["uid 2001;", "host-name EDGE-1;", "class ops;", "permissions [ view ];", "idle-timeout 0;"]


@pytest.mark.parametrize("line", NOISE)
@pytest.mark.parametrize("control_id, predicate", [
    ("MGMT-003", SOURCE_RESTRICTED),
    ("MGMT-005", "auth.password.encryption_service"),
    ("MGMT-009", "banner.login.present"),
    ("BOUNDARY-002", "boundary.source_routing.enabled"),
    ("LOG-002", NTP_AUTHENTICATED),
])
def test_a_line_that_states_nothing_can_only_teach_a_setting_it_names(line, control_id, predicate):
    """"The line is there" is evidence only when the line is the one that configures the setting."""
    with pytest.raises((MappingValidationError, ValueError)):
        teach(f"system {{\n  login {{\n    {line}\n  }}\n}}\n", control_id, 3, predicate, value=True)


@pytest.mark.parametrize("taught, control_id, predicate, value, subject", [
    # an unfamiliar word for a familiar concept: the line states "off", so it is the admin's to name
    ("hostname A\nmanagement-plane legacy-access disabled\n", "MGMT-001", PROTOCOL_ENABLED, False, "telnet"),
    ("hostname A\nadmin-origin enforcement enabled\n", "MGMT-003", SOURCE_RESTRICTED, True, None),
])
def test_an_unfamiliar_word_still_teaches_when_the_line_states_its_own_value(
        taught, control_id, predicate, value, subject):
    """Teaching exists for dialects nobody has a word list for; a stated on/off is the admin's to name."""
    assert teach(taught, control_id, 2, predicate, value=value).id is not None
    assert read(taught, predicate, subject) is value


def test_the_same_rule_holds_for_a_hand_written_presence_template():
    with pytest.raises(MappingValidationError):
        MappingRepository().save_mapping(LearnedMapping(
            concept="sneaky", normalized_field="", extraction_method=EXTRACTION_RECOGNIZER, confirmed=True,
            command_pattern="{neg} uid {any}", scope_template="user netops",
            predicate=SOURCE_RESTRICTED, example_line="uid 2001;"))


def test_a_storage_table_may_name_storage_types_but_never_a_password():
    from app.db.mappings import _refuse_secrets

    def storage(table: str) -> LearnedMapping:
        return LearnedMapping(concept="Password storage", normalized_field="", extraction_method=EXTRACTION_RECOGNIZER,
                              predicate="auth.password.storage",
                              command_pattern="set mgt-config users {any} {enum:storage} {any}",
                              constant_value=table, example_line="set mgt-config users admin phash <SECRET:password>")

    _refuse_secrets(storage('{"phash": "hashed"}'))
    with pytest.raises(MappingValidationError):
        _refuse_secrets(storage('{"phash": "hunter2"}'))
