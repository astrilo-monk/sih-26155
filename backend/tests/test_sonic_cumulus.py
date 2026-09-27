"""
White-box switches: SONiC ``config_db.json`` (a table per feature, one entry per name or address) and NVIDIA
Cumulus Linux NVUE (``nv set …``), read by seed knowledge. Sources for each seed: ``docs/seed-knowledge.md``.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.facts.recognizers import _keywords
from app.main import app
from app.structure.structured import flatten_json

DIALECTS = Path(__file__).resolve().parent / "fixtures" / "seed_dialects"
SECRETS = ("n0c-r3adonly", "Tac4csKey9")


def _scan(text: str, name: str) -> dict:
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        return TestClient(app).post("/api/scan", files=[("files", (name, text, "text/plain"))]).json()


def _statuses(name: str) -> dict:
    results = _scan((DIALECTS / name).read_text(encoding="utf-8"), name)["results"]
    statuses: dict[str, set] = {}
    for r in results:
        statuses.setdefault(r["control_id"], set()).add(r["status"])
    return statuses


def test_a_sonic_table_is_one_statement_per_entry():
    lines = flatten_json((DIALECTS / "sonic_secure.json").read_text(encoding="utf-8"))
    assert "SNMP_COMMUNITY n0c-r3adonly TYPE RO" in lines
    assert "SYSLOG_SERVER 10.20.0.5" in lines  # an entry with no attributes still states its key
    assert "SYSLOG_SERVER 10.20.0.6 port 514 vrf mgmt" in lines


@pytest.mark.parametrize("name, expected", [
    ("sonic_insecure.json", {"MGMT-004": {"fail"}, "MGMT-011": {"fail"}}),
    ("sonic_secure.json", {"MGMT-004": {"pass"}, "MGMT-011": {"fail"}, "LOG-001": {"pass"}, "MGMT-008": {"pass"}}),
    ("cumulus_insecure.conf", {"MGMT-004": {"fail"}, "MGMT-011": {"fail"}}),
    ("cumulus_secure.conf", {"MGMT-004": {"pass"}, "MGMT-011": {"fail"}, "LOG-001": {"pass"}, "MGMT-008": {"pass"}}),
])
def test_white_box_settings_decide(seeded_adaptive_db, name, expected):
    statuses = _statuses(name)
    assert {c: statuses[c] for c in expected} == expected


def test_a_disabled_ntp_server_is_not_a_time_source(seeded_adaptive_db):
    config = {"NTP_SERVER": {"10.0.0.1": {"admin_state": "disabled", "iburst": "on"}},
              "SNMP_COMMUNITY": {"n0c-view": {"TYPE": "RO"}}}
    results = _scan(json.dumps(config), "config_db.json")["results"]
    assert not any(r["control_id"] == "LOG-002" and r["status"] == "pass" for r in results)
    # the generic heuristic may still suspect one (the last on/off word, ``iburst on``, wins), never decide it
    assert all(f["assurance"] != "confirmed" for r in results for f in r["facts"] if f["field"] == "time.ntp.server")


@pytest.mark.parametrize("name", ["sonic_secure.json", "cumulus_secure.conf"])
def test_community_strings_and_keys_never_leave(seeded_adaptive_db, name):
    body = json.dumps(_scan((DIALECTS / name).read_text(encoding="utf-8"), name))
    assert not any(secret in body for secret in SECRETS)


def test_an_underscore_joins_words_in_one_identifier():
    assert _keywords("SYSLOG_SERVER {host} {rest}") == ["SYSLOG", "SERVER"]
    assert _keywords("idle-timeout {int}") == ["idle-timeout"]  # a hyphenated CLI word stays one keyword
