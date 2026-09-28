"""Every result carries its evidence chain: the requirements it answers and the normalized facts it read."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.main import app

ROOT = Path(__file__).resolve().parents[2]


def _scan(name):
    text = (ROOT / "backend" / "tests" / "fixtures" / "demo" / name).read_bytes()
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        return TestClient(app).post("/api/scan", files=[("files", (name, text, "text/plain"))]).json()


def test_a_result_links_requirement_field_value_and_line(seeded_adaptive_db):
    results = {r["control_id"]: r for r in _scan("cisco_edge_vulnerable.cfg")["results"]}
    ssh = results["MGMT-007"]
    assert ssh["facts"] == [{"field": "mgmt.ssh.version", "subject": None, "value": 1, "unit": None,
                             "assurance": "parser", "line_numbers": ssh["facts"][0]["line_numbers"]}]
    assert set(ssh["facts"][0]["line_numbers"]) <= set(ssh["evidence"]["line_numbers"])
    frameworks = {r["framework"] for r in ssh["requirements"]}
    assert {"NIST_800_53", "DISA_STIG", "ISO_27001", "CIS"} <= frameworks  # CIS: a confirmed Cisco device


def test_the_chain_never_shows_a_secret_or_a_foreign_benchmark(seeded_adaptive_db):
    scan = _scan("paloalto_fw_vulnerable.cfg")
    snmp = next(r for r in scan["results"] if r["control_id"] == "MGMT-004")
    assert snmp["facts"] and all(f["value"] == "<SECRET:redacted>" for f in snmp["facts"])
    assert "public" not in str([r["facts"] for r in scan["results"]])
    # a product benchmark (CIS Cisco / FortiGate) never maps onto a device it was not written for
    assert all(req["framework"] != "CIS" for r in scan["results"] for req in r["requirements"])


def test_the_catalog_lists_every_check_and_counts_distinct_requirements():
    from app.controls.catalog import CONTROLS

    catalog = TestClient(app).get("/api/catalog").json()
    assert [c["control_id"] for c in catalog["controls"]] == list(CONTROLS)
    assert catalog["requirement_total"] == sum(catalog["requirements"].values())
    assert set(catalog["requirements"]) == {"NIST_800_53", "CIS", "DISA_STIG", "ISO_27001"}
    cis = [r for c in catalog["controls"] for r in c["requirements"] if r["framework"] == "CIS"]
    assert cis and all(r["vendor"] in ("cisco_ios", "fortinet") for r in cis)
