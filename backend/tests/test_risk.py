"""Contextual risk: worst decided problem, exposure, attack paths and asset criticality, by a fixed formula."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.analysis.risk import device_risk
from app.main import app


def _fail(control_id, severity, assurance="parser"):
    return {"control_id": control_id, "title": control_id, "severity": severity, "status": "fail", "assurance": assurance}


def test_the_formula_adds_exposure_and_paths_and_scales_by_criticality():
    assert device_risk([], []) == {**device_risk([], []), "score": 0, "level": "low", "reasons": ["No confirmed problem"]}
    high = [_fail("MGMT-002", "high")]
    assert device_risk(high, [])["score"] == 45
    assert device_risk(high, [], internet_facing=True)["score"] == 65
    exposed = high + [_fail("MGMT-010", "critical")]
    risk = device_risk(exposed, [{}, {}, {}], criticality="critical")
    assert risk["score"] == 100 and risk["level"] == "critical"  # (60 + 20 + 20) × 1.3, capped
    assert risk["reasons"] == ["Worst confirmed problem is critical: MGMT-010", "Management is reachable from an "
                               "untrusted interface", "3 potential attack paths", "Asset criticality critical (×1.3)"]
    # a suspected problem never raises risk
    assert device_risk([_fail("MGMT-001", "critical", assurance="heuristic")], [])["score"] == 0


def test_upload_context_reaches_each_device(seeded_adaptive_db):
    cisco = (Path(__file__).resolve().parents[2] / "demo-sih" / "cisco_edge_vulnerable.cfg").read_bytes()
    client = TestClient(app)
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        scan = client.post("/api/scan", data={"criticality": "high", "internet_facing": "true"},
                           files=[("files", ("c.cfg", cisco, "text/plain"))]).json()
        bad = client.post("/api/scan", data={"criticality": "extreme"}, files=[("files", ("c.cfg", cisco, "text/plain"))])
    risk = scan["devices"][0]["risk"]
    assert risk["level"] == "critical" and "Asset criticality high (×1.15)" in risk["reasons"]
    assert "Marked as facing the internet at upload" in risk["reasons"]
    assert bad.status_code == 422
