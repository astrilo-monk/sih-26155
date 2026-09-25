"""
Phase 0 -safety net for the control-first refactor.

``snapshots/phase0_findings.json`` records what the engine produced for every
Cisco / FortiGate fixture and sample *before* the refactor started
(rule id, severity and cited line numbers per finding, plus vendor and score).
Every later phase must keep these known-vendor results identical.

Regenerate only for a deliberate, reviewed semantics change.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app

REPO = Path(__file__).resolve().parents[2]
SNAPSHOT = json.loads((Path(__file__).parent / "snapshots" / "phase0_findings.json").read_text())
BASELINE_TEST_COUNT = "248 passed, 2 skipped"  # full backend suite before Phase 0


def _scan_offline(client: TestClient, path: Path) -> dict:
    no_ai = MagicMock(side_effect=AssertionError("known-vendor scans must not call the AI"))
    with patch("app.api.routes.scan.interpret_lines", no_ai), \
         patch("app.api.routes.scan.is_available", return_value=False):
        resp = client.post("/api/scan", files=[("files", (path.name, path.read_bytes(), "text/plain"))])
    assert resp.status_code == 200, resp.text
    return resp.json()


# The controls the snapshot was recorded with. Controls added later answer new questions: they may add findings,
# but never change these (the deprecated ``score`` counts every finding, so it moves with the catalog).
PHASE0_CONTROLS = {
    "MGMT-001", "MGMT-002", "MGMT-003", "MGMT-004", "MGMT-005", "MGMT-006", "MGMT-007", "MGMT-008", "MGMT-009",
    "BOUNDARY-001", "BOUNDARY-002", "BOUNDARY-003", "LOG-001", "LOG-002", "CRYPTO-001",
}


@pytest.mark.parametrize("entry", SNAPSHOT["entries"], ids=lambda e: e["file"])
def test_known_vendor_findings_match_phase0_snapshot(entry):
    data = _scan_offline(TestClient(app), REPO / entry["file"])

    assert data["devices"][0]["vendor"] == entry["vendor"]
    findings = sorted([f["rule_id"], f["severity"], f["line_numbers"]] for f in data["findings"]
                      if f["rule_id"] in PHASE0_CONTROLS)
    assert findings == entry["findings"]


def test_snapshot_covers_both_known_vendors():
    vendors = {e["vendor"] for e in SNAPSHOT["entries"]}
    assert vendors == {"cisco_ios", "fortinet"}


def test_unknown_cfg_reports_telnet_on_lines_70_71():
    """Phase 0 known defect, fixed by Phase 5 lexicon heuristics (suspected, not scored)."""
    data = _scan_offline(TestClient(app), REPO / "sample" / "unknown.cfg")
    telnet = [f for f in data["findings"] if f["rule_id"] == "MGMT-001"]
    assert telnet and {70, 71} <= set(telnet[0]["line_numbers"])
    assert telnet[0]["assurance"] == "heuristic"
