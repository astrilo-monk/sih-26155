"""
Brace-block configurations read by set-style knowledge (``facts.recognizers.set_form``).

A Junos leaf inside ``snmp { community public { … } }`` states what the flat
``set snmp community public …`` line states, so a seed taught in either form reads both, and the
evidence cites the line in the uploaded file.
"""

from pathlib import Path

import pytest

from app.facts.predicates import SNMP_COMMUNITY
from app.facts.recognizers import recognizer_facts, set_form
from app.models.results import Status
from app.structure.tokenizer import tokenize
from tests.test_seed_knowledge import _facts, _results, _telnet

DIALECTS = Path(__file__).resolve().parent / "fixtures" / "seed_dialects"
DECIDED = (Status.PASS, Status.FAIL)


def _decided(text: str) -> dict:
    return {c: r.status for c, r in _results(text).items() if r.status in DECIDED}


def test_braces_file_decides_what_its_set_twin_decides(seeded_adaptive_db):
    braces = _decided((DIALECTS / "junos_braces.conf").read_text(encoding="utf-8"))
    flat = _decided((DIALECTS / "junos_set.conf").read_text(encoding="utf-8"))
    assert braces == flat
    assert {"MGMT-004", "MGMT-011"} <= set(braces)  # read only by set-style seeds before


def test_evidence_cites_the_leaf_line_of_the_uploaded_file(seeded_adaptive_db):
    text = (DIALECTS / "junos_braces.conf").read_text(encoding="utf-8")
    snmp = [f for f in _facts(text) if f.predicate == SNMP_COMMUNITY]
    line = text.splitlines().index("        authorization read-only;") + 1
    assert [f.evidence.line_numbers for f in snmp] == [[line]]


def test_a_header_and_its_leaf_state_one_account_once(seeded_adaptive_db):
    text = "system {\n  login {\n    user admin {\n      class super-user;\n    }\n  }\n}\n"
    accounts = [f for f in recognizer_facts(text.splitlines())[0] if f.predicate == "auth.account.name"]
    assert [f.evidence.line_numbers for f in accounts] == [[3]]


@pytest.mark.parametrize("config", [
    "system {\n  services {\n    inactive: telnet;\n  }\n}\n",
    "system {\n  inactive: services {\n    telnet;\n  }\n}\n",
])
def test_inactive_statements_configure_nothing(seeded_adaptive_db, config):
    assert _telnet(config) is None


def test_block_comments_are_not_section_headers(seeded_adaptive_db):
    assert _telnet("/* management\n   services */\nsystem {\n  services {\n    telnet;\n  }\n}\n") is True


@pytest.mark.parametrize("config", [
    # IOS indentation, FortiGate config/edit, RouterOS sections: no terminator, never flattened
    "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n",
    "config system global\n    set admintimeout 5\nend\n",
    "/ip service\nset telnet disabled=no\n",
])
def test_only_terminated_brace_leaves_have_a_set_form(config):
    assert [set_form(s) for s in tokenize(config.splitlines())] == [None] * len(tokenize(config.splitlines()))


def test_set_form_of_a_nested_leaf():
    statements = tokenize("snmp {\n  community public {\n    authorization read-only;\n  }\n}\n".splitlines())
    assert set_form(statements[-1]) == "set snmp community public authorization read-only"
