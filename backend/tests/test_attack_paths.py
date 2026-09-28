"""Potential attack paths open only on decided FAILs, cite their lines, and say which fix breaks them."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.analysis.attack_paths import attack_paths
from app.main import app


def _fail(control_id, assurance="confirmed", line=1):
    return {"control_id": control_id, "status": "fail", "assurance": assurance,
            "evidence": {"line_numbers": [line], "lines": [f"line {line}"]}}


def test_a_path_needs_every_step_decided():
    takeover = [_fail("MGMT-003", line=1), _fail("MGMT-001", line=2), _fail("AUTH-003", line=3)]
    [path] = [p for p in attack_paths(takeover) if p["path_id"] == "remote-takeover"]
    assert [s["controls"][0]["control_id"] for s in path["steps"]] == ["MGMT-003", "MGMT-001", "AUTH-003"]
    assert path["steps"][1]["controls"][0]["lines"] == [{"number": 2, "text": "line 2"}]
    # one step missing, or only suspected (heuristic), and the path is gone
    assert not [p for p in attack_paths(takeover[:2]) if p["path_id"] == "remote-takeover"]
    suspected = takeover[:2] + [_fail("AUTH-003", assurance="heuristic")]
    assert not [p for p in attack_paths(suspected) if p["path_id"] == "remote-takeover"]


def test_the_cheapest_step_breaks_the_path():
    results = [_fail("MGMT-003"), _fail("MGMT-010"), _fail("MGMT-001"), _fail("MGMT-002"), _fail("MGMT-008")]
    [path] = [p for p in attack_paths(results) if p["path_id"] == "remote-takeover"]
    assert path["break_with"] == ["MGMT-008"] and path["break_step"] == "Log in as an administrator"


def test_the_scan_reports_the_paths_of_each_device(seeded_adaptive_db):
    cisco = (Path(__file__).resolve().parents[2] / "backend" / "tests" / "fixtures" / "demo" / "cisco_edge_vulnerable.cfg").read_bytes()
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        scan = TestClient(app).post("/api/scan", files=[("files", ("c.cfg", cisco, "text/plain"))]).json()
    paths = {p["path_id"]: p for p in scan["attack_paths"]}
    assert paths["remote-takeover"]["severity"] == "critical" and paths["remote-takeover"]["config_index"] == 0
    assert paths["remote-takeover"]["break_with"] == ["MGMT-003"]
    assert "perimeter-bypass" in paths
    assert "public" not in str(scan["attack_paths"])  # quotes only redacted evidence


def test_the_pdf_report_explains_each_path(seeded_adaptive_db):
    from app.api.routes.scan import build_scan_response
    from app.reporting.report import report_blocks, report_text

    cisco = (Path(__file__).resolve().parents[2] / "backend" / "tests" / "fixtures" / "demo" / "cisco_edge_vulnerable.cfg").read_bytes()
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        scan_id = TestClient(app).post("/api/scan", files=[("files", ("c.cfg", cisco, "text/plain"))]).json()["scan_id"]
    text = report_text(report_blocks(build_scan_response(scan_id), 0))
    assert "Potential attack paths" in text and "Remote takeover through the management plane (CRITICAL)" in text
    assert "Result: Full administrative control of the device" in text
    assert 'Break it: fix MGMT-003 (the "Reach the login" step)' in text


def test_each_device_carries_its_own_posture(seeded_adaptive_db):
    root = Path(__file__).resolve().parents[2] / "backend" / "tests" / "fixtures" / "demo"
    files = [("files", (n, (root / n).read_bytes(), "text/plain"))
             for n in ("cisco_edge_vulnerable.cfg", "paloalto_fw_vulnerable.cfg")]
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        scan = TestClient(app).post("/api/scan", files=files).json()
    assert all(isinstance(d["posture"], int) and 0 < d["coverage"] <= 100 for d in scan["devices"])
    assert {p["config_index"] for p in scan["attack_paths"]} == {0, 1}


def test_the_executive_summary_is_short_and_leads_with_what_to_do(seeded_adaptive_db):
    from app.api.routes.remediation import _device_plan, _stored
    from app.api.routes.scan import build_scan_response
    from app.reporting.report import executive_blocks, report_blocks, report_text

    cisco = (Path(__file__).resolve().parents[2] / "backend" / "tests" / "fixtures" / "demo" / "cisco_edge_vulnerable.cfg").read_bytes()
    client = TestClient(app)
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        scan_id = client.post("/api/scan", files=[("files", ("c.cfg", cisco, "text/plain"))]).json()["scan_id"]
    scan, plan = build_scan_response(scan_id), _device_plan(_stored(scan_id), 0, {})
    summary = report_text(executive_blocks(scan, 0, plan))
    assert summary.startswith("Executive summary") and "How an attacker could chain these problems" in summary
    what = summary.split("What to do first")[1].splitlines()
    assert what[2].startswith("MGMT-003") and "breaks an attack path" in what[2]  # the path breaker comes first
    assert len(summary) < len(report_text(report_blocks(scan, 0, plan))) / 3
    pdf = client.post("/api/report", json={"scan_id": scan_id, "variant": "executive"})
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
