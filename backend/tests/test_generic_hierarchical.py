"""
Generic engine on hierarchical, terminator-separated dialects.

A curly-brace dialect keeps the nouns in the block header and ends every statement with ``;``:

    system { ntp { server 192.0.2.10; } }

No vendor grammar is involved anywhere below: every assertion is about the generic tokenizer,
the lexicon heuristics and the recognizer template language.
"""

import pytest

from app.adaptive.matcher import EXTRACTION_RECOGNIZER, PatternError, match_recognizer, recognizer_slot
from app.controls.evaluate import evaluate_controls
from app.db.mappings import LearnedMapping, MappingRepository
from app.facts.heuristics import heuristic_facts
from app.facts.predicates import IDLE_TIMEOUT, LOG_REMOTE_DESTINATION, NTP_SERVER, PERMIT_ANY, PROTOCOL_ENABLED, \
    SSH_VERSION
from app.facts.recognizers import (
    RECOGNIZER_PREDICATES, RecognizerError, draft_recognizer, recognizer_facts, validate_recognizer,
)
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Status


def _facts(text: str, predicate: str) -> list:
    return [f for f in heuristic_facts(text.splitlines()) if f.predicate == predicate]


def _value(text: str, predicate: str, subject=None):
    facts = [f for f in _facts(text, predicate) if subject is None or f.subject == subject]
    return facts[0].value if len(facts) == 1 else facts


def _draft(text: str, line: int) -> LearnedMapping:
    fields = draft_recognizer(text.splitlines(), RECOGNIZER_PREDICATES, line)
    return LearnedMapping(concept="c", normalized_field="", extraction_method=EXTRACTION_RECOGNIZER,
                          confirmed=True, **fields)


def _unknown(text: str) -> NormalizedConfig:
    return NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="u"),
                            raw_config=text, raw_lines=text.splitlines())


def _control(text: str, control_id: str):
    return next(r for r in evaluate_controls(_unknown(text)) if r.control_id == control_id)


# -- the draft a scan offers must pass the validator that saves it -----------

NTP_CFG = "system {\n    ntp {\n        server 192.168.10.10;\n    }\n}\n"
SSH_CFG = "system {\n    services {\n        ssh {\n            protocol-version v2;\n        }\n    }\n}\n"
TELNET_CFG = "system {\n    services {\n        telnet;\n    }\n}\n"
TIMEOUT_CFG = "system {\n    login {\n        session-timeout 30 minutes;\n    }\n}\n"
UNITLESS_CFG = "system {\n    login {\n        idle-timeout 30;\n    }\n}\n"


@pytest.mark.parametrize("text, line, slot, scope", [
    (NTP_CFG, 3, "ip", "ntp"),                 # value read from an {ip} slot
    (SSH_CFG, 4, "int", "ssh"),                # a version written as v2, not a bare number
    (TELNET_CFG, 3, None, "services"),         # presence: no slot, a constant value
    (TIMEOUT_CFG, 3, "duration", "login"),     # numeric slot, unit carried into the slot
])
def test_a_generated_draft_passes_its_own_validation_and_compiles(text, line, slot, scope):
    draft = _draft(text, line)
    validate_recognizer(draft)  # the same gate a hand-edited recognizer goes through
    assert recognizer_slot(draft.command_pattern)[0] == slot
    assert draft.scope_template == scope
    assert match_recognizer(draft.command_pattern, draft.example_line) is not None
    assert MappingRepository().save_mapping(draft).id is not None


def test_only_a_unit_a_human_must_choose_blocks_a_draft():
    # the line states a number with no unit: nothing in the configuration says which, so the admin picks
    draft = _draft(UNITLESS_CFG, 3)
    assert draft.command_pattern == "idle-timeout {duration}"
    with pytest.raises(RecognizerError, match="unit"):
        validate_recognizer(draft)
    draft.command_pattern = "idle-timeout {duration:min}"
    validate_recognizer(draft)


def test_the_saved_draft_answers_its_own_configuration_decisively():
    MappingRepository().save_mapping(_draft(NTP_CFG, 3))
    facts, skip = recognizer_facts(NTP_CFG.splitlines())
    assert [(f.predicate, f.value, f.assurance) for f in facts] == [
        (NTP_SERVER, ["192.168.10.10"], Assurance.CONFIRMED)]
    assert 3 in skip  # the heuristic no longer re-reads a line a recognizer answered


# -- statement terminators are punctuation, not part of a token --------------

@pytest.mark.parametrize("pattern, line, expected", [
    ("server {ip};", "server 192.0.2.10;", "192.0.2.10"),
    ("server {ip}", "server 192.0.2.10;", "192.0.2.10"),
    ("server {ip};", "server 192.0.2.10", "192.0.2.10"),
    ("protocol {enum:protocol};", "    protocol tcp;", "tcp"),
    ("timeout {duration:s};", "timeout 600;", "600"),
    ("protocol-version {enum:version};", "protocol-version v2;", "v2"),
])
def test_a_terminated_statement_is_representable_and_matches(pattern, line, expected):
    assert match_recognizer(pattern, line)[2] == expected


def test_a_terminator_never_hides_a_real_mismatch():
    assert match_recognizer("server {ip};", "server host.example.com;") is None
    assert match_recognizer("server {ip};", "peer 192.0.2.10;") is None
    with pytest.raises(PatternError):
        recognizer_slot("server {ip}x;")


# -- scope contributes specificity, and never substitutes for the statement --

def _ntp_recognizer(**overrides) -> LearnedMapping:
    values = dict(concept="NTP", normalized_field="", extraction_method=EXTRACTION_RECOGNIZER, confirmed=True,
                  predicate=NTP_SERVER, command_pattern="server {ip}", scope_template="ntp",
                  example_line="server 192.168.10.10;")
    values.update(overrides)
    return LearnedMapping(**values)


def test_a_one_keyword_leaf_is_specific_enough_only_with_its_scope():
    validate_recognizer(_ntp_recognizer())
    with pytest.raises(RecognizerError, match="keywords"):
        validate_recognizer(_ntp_recognizer(scope_template=None))
    with pytest.raises(RecognizerError, match="literal keyword"):
        # a scope can never carry a recognizer on its own
        validate_recognizer(_ntp_recognizer(command_pattern="{ip}", scope_template="ntp server"))


def test_the_same_leaf_keyword_in_two_scopes_does_not_collide():
    repo = MappingRepository()
    repo.save_mapping(_ntp_recognizer())
    repo.save_mapping(_ntp_recognizer(predicate=LOG_REMOTE_DESTINATION, concept="Syslog", scope_template="syslog"))
    config = ("system {\n    ntp {\n        server 192.168.10.10;\n    }\n"
              "    syslog {\n        server 10.9.9.9;\n    }\n"
              "    dns {\n        server 8.8.8.8;\n    }\n}\n")
    facts, _ = recognizer_facts(config.splitlines())
    assert {f.predicate: (f.value, f.evidence.line_numbers) for f in facts} == {
        NTP_SERVER: (["192.168.10.10"], [3]),
        LOG_REMOTE_DESTINATION: (["10.9.9.9"], [6]),
    }  # the DNS server matched neither scope


# -- presence states an enabled feature; absence still states nothing --------

@pytest.mark.parametrize("statement, expected", [
    ("telnet;", True),                        # presence
    ("no telnet;", False),                    # negated form
    ("telnet disabled;", False),              # explicit disable
    ("telnet;\n        no telnet;", None),    # contradiction -> undetermined, never a quiet PASS
])
def test_presence_polarity(statement, expected):
    text = f"system {{\n    services {{\n        {statement}\n    }}\n}}\n"
    assert _value(text, PROTOCOL_ENABLED, "telnet") == expected


def test_a_switched_off_block_wins_over_a_declaration_inside_it():
    text = "system {\n    services {\n        state disabled;\n        telnet;\n    }\n}\n"
    assert _value(text, PROTOCOL_ENABLED, "telnet") is False


def test_absence_is_never_a_pass_for_an_unknown_vendor():
    text = "system {\n    services {\n        ssh;\n    }\n}\n"
    assert _facts(text, PROTOCOL_ENABLED) == []
    assert _control(text, "MGMT-001").status == Status.NOT_CONFIGURED


def test_a_bare_statement_outside_a_service_block_states_nothing():
    # a word in a traffic rule is not a management service being switched on
    text = "firewall {\n    filter INBOUND {\n        term t {\n            telnet;\n        }\n    }\n}\n"
    assert _facts(text, PROTOCOL_ENABLED) == []


# -- version-style values ---------------------------------------------------

def _ssh(stated: str) -> str:
    return (f"system {{\n    services {{\n        ssh {{\n            protocol-version {stated};\n"
            f"        }}\n    }}\n}}\n")


@pytest.mark.parametrize("stated, expected", [
    ("v1", 1), ("v2", 2), ("v3", 3), ("2", 2), ("3", 3), ("ver2", 2), ("version2", 2),
])
def test_a_version_may_carry_a_version_prefix(stated, expected):
    assert _value(_ssh(stated), SSH_VERSION) == expected


@pytest.mark.parametrize("stated", ["vlan10", "aes256", "ssh2rsa", "compat-v2x"])
def test_a_word_that_merely_contains_a_number_is_not_a_version(stated):
    assert _facts(_ssh(stated), SSH_VERSION) == []


def test_a_version_prefix_is_not_read_as_a_number_elsewhere():
    # the same token under a timeout keyword stays a word, not a duration
    text = "system {\n    login {\n        idle-timeout v5;\n    }\n}\n"
    assert _facts(text, IDLE_TIMEOUT) == []


# -- a rule split over sibling statements ------------------------------------

def _policy(name: str, source: str, destination: str, action: str) -> str:
    return (f"    policy {name} {{\n        match {{\n            source-address {source};\n"
            f"            destination-address {destination};\n        }}\n"
            f"        then {{\n            {action};\n        }}\n    }}\n")


def test_only_an_any_to_any_permit_triggers_the_control():
    text = ("policies {\n"
            + _policy("wide-open", "any", "any", "permit")
            + _policy("narrow-source", "10.0.0.0/8", "any", "permit")
            + _policy("wide-deny", "any", "any", "deny")
            + "}\n")
    facts = _facts(text, PERMIT_ANY)
    assert len(facts) == 1, facts
    assert facts[0].value is True
    assert facts[0].evidence.line_numbers == [4, 5, 8]  # every line of the rule is cited
    assert "wide-open" in facts[0].scope
    assert _control(text, "BOUNDARY-001").status == Status.FAIL


def test_rules_in_sibling_blocks_are_never_merged():
    # the wildcards and the permit belong to different policies
    text = ("policies {\n"
            + _policy("a", "any", "any", "deny")
            + _policy("b", "10.0.0.0/8", "192.168.0.0/16", "permit")
            + "}\n")
    assert _facts(text, PERMIT_ANY) == []


def test_a_narrowing_selector_anywhere_in_the_rule_means_it_is_not_all_traffic():
    text = ("policies {\n    policy web {\n        match {\n            source-address any;\n"
            "            destination-address any;\n            application [ http https ];\n        }\n"
            "        then {\n            permit;\n        }\n    }\n}\n")
    assert _facts(text, PERMIT_ANY) == []


def test_a_flat_single_line_rule_still_works():
    assert _value("access-list 100 permit ip any any\n", PERMIT_ANY) is True


# -- a confirmed recognizer generalizes by pattern, not by the line it saw ---

def test_a_confirmed_recognizer_generalizes_across_values_and_layout():
    MappingRepository().save_mapping(_draft(NTP_CFG, 3))
    other = ("routing {\n  static {\n    route 0.0.0.0/0;\n  }\n}\n"
             "system {\n  host-name OTHER-BOX;\n  ntp {\n\t  server 10.20.30.40;\n  }\n}\n")
    facts, _ = recognizer_facts(other.splitlines())
    assert [(f.value, f.evidence.line_numbers, f.assurance) for f in facts] == [
        (["10.20.30.40"], [9], Assurance.CONFIRMED)]


@pytest.mark.parametrize("name, indent, extra", [
    ("allow-all", "    ", ""),
    ("RULE_7", "\t", "        description \"edge policy\";\n"),
    ("p", "  ", "        count;\n"),
])
def test_composition_reads_the_structure_not_the_names(name, indent, extra):
    text = (f"security {{\n  policies {{\n{indent}policy {name} {{\n{extra}"
            f"{indent}  from {{\n{indent}    source-address any;\n{indent}    destination-address any;\n"
            f"{indent}  }}\n{indent}  then {{\n{indent}    permit;\n{indent}  }}\n{indent}}}\n  }}\n}}\n")
    assert _value(text, PERMIT_ANY) is True


def test_a_confirmed_recognizer_does_not_fire_in_an_unrelated_scope():
    MappingRepository().save_mapping(_draft(NTP_CFG, 3))
    other = "system {\n    dns {\n        server 10.20.30.40;\n    }\n}\n"
    assert recognizer_facts(other.splitlines())[0] == []
