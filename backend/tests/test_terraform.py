"""
Terraform (HCL): blocks flattened in place (``structure.structured.flatten_hcl``), read by seed knowledge.

Each block becomes one statement on its own header line, so evidence cites the uploaded file; a value the
file does not resolve (``var.x``) never decides a result.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.controls.evaluate import platform_profile
from app.main import app
from app.structure.structured import flatten_hcl

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TF = FIXTURES / "terraform"


def _scan(path: Path) -> dict:
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        response = TestClient(app).post("/api/scan", files=[("files", (path.name, path.read_bytes(), "text/plain"))])
    return {r["control_id"]: r for r in response.json()["results"]}


# ── flattening ───────────────────────────────────────────────────────────────

def test_a_block_becomes_one_statement_on_its_own_line():
    text = ('resource "aws_security_group" "web" {\n'
            '  name = "web sg"   # a comment\n'
            '  description = "free text"\n'
            '  ingress {\n'
            '    from_port   = 22\n'
            '    cidr_blocks = [\n'
            '      "0.0.0.0/0",\n'
            '      var.office,\n'
            '    ]\n'
            '  }\n'
            '}\n')
    assert flatten_hcl(text) == [
        'resource aws_security_group web name "web sg" {', "", "",
        "ingress cidr_blocks ${var.office} cidr_blocks 0.0.0.0/0 from_port 22 {", "", "", "", "", "",
        "}", "}"]


def test_expressions_and_heredocs_are_unresolved_never_values():
    text = ('resource "aws_iam_policy" "p" {\n'
            '  policy = jsonencode({\n'
            '    Effect = "Allow"\n'
            '  })\n'
            '  user_data = <<EOF\n'
            'ingress {\n'
            'EOF\n'
            '  prefix = "${var.net}/32"\n'
            '}\n')
    flat = flatten_hcl(text)
    assert flat[0] == "resource aws_iam_policy p policy ${expression} prefix ${var.net}/32 {"
    assert len(flat) == len(text.splitlines()) and not any(flat[1:-1])


@pytest.mark.parametrize("path", [FIXTURES / "seed_dialects" / "junos.conf", FIXTURES / "seed_dialects" / "panos.conf",
                                  FIXTURES / "seed_dialects" / "routeros.rsc", FIXTURES / "seed_dialects" / "arista.conf"])
def test_other_configurations_are_not_hcl(path):
    assert flatten_hcl(path.read_text(encoding="utf-8")) is None


def test_json_and_ios_are_not_hcl():
    assert flatten_hcl('{"a": {"b": 1}}') is None
    assert flatten_hcl("hostname R1\ninterface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n") is None


# ── verdicts ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name, expected", [
    # (MGMT-003, BOUNDARY-001) with the lines cited in the uploaded file
    ("aws_insecure.tf", {"MGMT-003": ("fail", [10, 34]), "BOUNDARY-001": ("fail", [18])}),
    ("azure_insecure.tf", {"MGMT-003": ("fail", [7]), "BOUNDARY-001": ("fail", [20])}),
    ("gcp_insecure.tf", {"MGMT-003": ("fail", [8]), "BOUNDARY-001": ("fail", [19])}),
    ("aws_secure.tf", {"MGMT-003": ("pass", [10, 18]), "BOUNDARY-001": ("unknown", [])}),
    # the Azure and GCP seeds only recognise the open form: a restricted rule is not proof of a restriction
    ("azure_secure.tf", {"MGMT-003": ("unknown", []), "BOUNDARY-001": ("unknown", [])}),
    ("gcp_secure.tf", {"MGMT-003": ("unknown", []), "BOUNDARY-001": ("unknown", [])}),
])
def test_cloud_rules_decide_on_the_rule_line(seeded_adaptive_db, name, expected):
    results = _scan(TF / name)
    assert {c: (results[c]["status"], results[c]["evidence"]["line_numbers"]) for c in expected} == expected


def test_a_cited_line_is_the_rule_block_in_the_uploaded_file(seeded_adaptive_db):
    lines = (TF / "aws_insecure.tf").read_text(encoding="utf-8").splitlines()
    assert lines[10 - 1].strip() == "ingress {" and lines[34 - 1].startswith('resource "aws_vpc_security_group_ingress_rule"')


def test_unresolved_variables_never_decide(seeded_adaptive_db):
    results = _scan(TF / "aws_variables.tf")
    assert results["MGMT-003"]["status"] == "unknown"
    assert results["BOUNDARY-001"]["status"] == "unknown"


# ── platform ─────────────────────────────────────────────────────────────────

def test_device_only_checks_do_not_apply_to_terraform(seeded_adaptive_db):
    results = _scan(TF / "aws_insecure.tf")
    assert results["MGMT-001"]["status"] == results["AUTH-003"]["status"] == results["LOG-001"]["status"] == "n_a"
    assert sum(r["status"] == "n_a" for r in results.values()) == 20


def test_the_terraform_profile_is_decided_by_top_level_blocks():
    flat = flatten_hcl((TF / "gcp_insecure.tf").read_text(encoding="utf-8"))
    assert platform_profile(flat)["name"] == "Terraform (HCL)"
    junos = (FIXTURES / "seed_dialects" / "junos.conf").read_text(encoding="utf-8").splitlines()
    assert platform_profile(junos) is None
