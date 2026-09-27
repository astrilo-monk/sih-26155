"""
Azure NSG (``az network nsg show`` / ``nsg rule list``) and GCP firewall (``gcloud compute firewall-rules list
--format=json``) exports: flattened one rule per line, read by seed knowledge. Only an Allow / INGRESS rule
from any source counts; everything a network security group cannot have is N/A.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.structure.structured import flatten_json

CLOUD = Path(__file__).resolve().parent / "fixtures" / "cloud_json"


def _scan(text: str, name: str = "export.json") -> dict:
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        response = TestClient(app).post("/api/scan", files=[("files", (name, text, "application/json"))])
    return {r["control_id"]: r for r in response.json()["results"]}


def _verdicts(text: str) -> tuple:
    results = _scan(text)
    return results["MGMT-003"]["status"], results["BOUNDARY-001"]["status"]


def _gcp() -> list:
    return json.loads((CLOUD / "gcp_firewall_insecure.json").read_text(encoding="utf-8"))


def _azure() -> dict:
    return json.loads((CLOUD / "azure_nsg_insecure.json").read_text(encoding="utf-8"))


# ── flattening ───────────────────────────────────────────────────────────────

def test_a_gcp_rule_keeps_its_ports_with_its_source_and_its_allowed_key():
    first = flatten_json(json.dumps(_gcp()))[0]
    assert first.startswith("allowed IPProtocol tcp ports 22 direction INGRESS disabled false")
    assert first.endswith("sourceRanges 0.0.0.0/0")
    assert "selfLink" not in first and "creationTimestamp" not in first and " id " not in first


def test_a_named_object_is_its_own_line_even_with_one_rule():
    nsg = _azure()
    nsg["securityRules"] = nsg["securityRules"][:1]
    lines = flatten_json(json.dumps(nsg))
    assert lines[1].startswith("securityRules access Allow") and "securityRules" not in lines[0]


# ── verdicts ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name, expected", [
    ("azure_nsg_insecure.json", ("fail", "fail")),
    ("gcp_firewall_insecure.json", ("fail", "fail")),
    # open rules only are read: a restricted or denying rule is not proof of anything (undecided, never PASS)
    ("azure_nsg_secure.json", ("unknown", "unknown")),
    ("gcp_firewall_secure.json", ("unknown", "unknown")),
])
def test_open_rules_fail(seeded_adaptive_db, name, expected):
    assert _verdicts((CLOUD / name).read_text(encoding="utf-8")) == expected


def test_a_denied_or_disabled_gcp_rule_is_not_a_permit(seeded_adaptive_db):
    rules = _gcp()
    rules[1]["denied"] = rules[1].pop("allowed")
    rules[0]["disabled"] = True
    assert _verdicts(json.dumps(rules)) == ("unknown", "unknown")


def test_an_azure_deny_or_outbound_rule_is_not_a_permit(seeded_adaptive_db):
    nsg = _azure()
    nsg["securityRules"][0]["direction"] = "Outbound"
    nsg["securityRules"][1]["access"] = "Deny"
    assert _verdicts(json.dumps(nsg)) == ("unknown", "unknown")


def test_the_rule_list_form_reads_the_same(seeded_adaptive_db):
    assert _verdicts(json.dumps(_azure()["securityRules"])) == ("fail", "fail")


@pytest.mark.parametrize("name, profile_rules", [("azure_nsg_insecure.json", 20), ("gcp_firewall_insecure.json", 20)])
def test_device_only_checks_do_not_apply(seeded_adaptive_db, name, profile_rules):
    results = _scan((CLOUD / name).read_text(encoding="utf-8"))
    assert sum(r["status"] == "n_a" for r in results.values()) == profile_rules
    assert results["MGMT-001"]["status"] == "n_a" and results["LOG-001"]["status"] == "n_a"
