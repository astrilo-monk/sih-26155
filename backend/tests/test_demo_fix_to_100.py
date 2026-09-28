"""
The fix-to-100 demo files (demo-sih/README.md): a bad first scan, every problem fixed, the corrected file rescanned
to posture 100 with no findings. Pinned so the video's story keeps holding.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app

DEMO = Path(__file__).resolve().parents[2] / "demo-sih"

PALOALTO_COMMANDS = {
    "MGMT-008": "set shared server-profile tacplus TACACS-MGMT server TAC1 address 10.60.99.30",
    "MGMT-009": 'set deviceconfig system login-banner "Authorized access only. Activity is monitored."',
    "LOG-001": "set deviceconfig system syslog-server 10.60.99.50",
    "LOG-002": "set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key",
    "AUTH-002": "set mgt-config password-complexity minimum-length 12",
}
UNKNOWN_TEACH = {"MGMT-001": 16, "MGMT-007": 18, "MGMT-006": 20}
UNKNOWN_COMMANDS = {
    "MGMT-001": "remote-console protocol ssh",
    "MGMT-007": "secure-shell protocol-version 2",
    "MGMT-006": "operator inactivity-lock 10 minutes",
}


def _scan(client, name, text):
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        response = client.post("/api/scan", files=[("files", (name, text.encode(), "text/plain"))])
    assert response.status_code == 200, response.text
    return response.json()


def _confirm_commands(client, scan, commands):
    host = scan["devices"][0]["hostname"]
    for rule, command in commands.items():
        body = {"scan_id": scan["scan_id"], "rule_id": rule, "device_hostname": host, "config_index": 0}
        client.post("/api/remediation/candidate", json={**body, "command": command})
        assert client.post("/api/remediation/candidate/verify", json=body).json()["status"] == "verified", rule
        client.post("/api/remediation/candidate/confirm", json=body)


def _rescan_corrected(client, scan, name):
    fixed = client.post("/api/download-fixed", json={"scan_id": scan["scan_id"], "include_confirmed": True})
    assert fixed.status_code == 200, fixed.text
    return _scan(client, name, fixed.text)


def test_cisco_every_problem_is_fixed_in_one_click(seeded_adaptive_db):
    client = TestClient(app)
    text = (DEMO / "cisco_oneclick.cfg").read_text()
    before = _scan(client, "cisco_oneclick.cfg", text)
    assert before["posture"] < 50 and before["total_findings"] >= 10
    after = _rescan_corrected(client, before, "cisco_oneclick.cfg")
    assert (after["posture"], after["total_findings"]) == (100, 0)


def test_three_fortigates_in_one_upload_are_fixed_together(seeded_adaptive_db):
    import io
    import zipfile

    client = TestClient(app)
    files = [("files", (p.name, p.read_bytes(), "text/plain")) for p in sorted((DEMO / "fortigate").glob("*.conf"))]
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        before = client.post("/api/scan", files=files).json()
    assert len(before["devices"]) == 3 and before["total_findings"] >= 10
    assert [f["check"] for f in before["fleet_findings"]] == ["ntp-mismatch"]  # visible only across devices
    fixed = client.post("/api/download-fixed", json={"scan_id": before["scan_id"]})
    with zipfile.ZipFile(io.BytesIO(fixed.content)) as z:
        corrected = [("files", (n, z.read(n), "text/plain")) for n in z.namelist()]
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        after = client.post("/api/scan", files=corrected).json()
    assert (after["posture"], after["total_findings"], len(after["devices"])) == (100, 0, 3)


def test_paloalto_is_fixed_by_the_engine_and_by_typed_commands(seeded_adaptive_db):
    client = TestClient(app)
    before = _scan(client, "paloalto_ai_human.cfg", (DEMO / "paloalto_ai_human.cfg").read_text())
    assert before["posture"] < 50 and before["total_findings"] == 10
    _confirm_commands(client, before, PALOALTO_COMMANDS)
    after = _rescan_corrected(client, before, "paloalto_ai_human.cfg")
    assert (after["posture"], after["total_findings"]) == (100, 0)


def test_a_unit_written_as_its_own_word_is_taught_through_the_page(seeded_adaptive_db):
    """Found recording the demo: ``operator inactivity-lock 0 minutes`` taught by picking what it says was refused
    ("states no unit"), because the unit is the word after the number."""
    client = TestClient(app)
    scan = _scan(client, "unknown_vendor.cfg", (DEMO / "unknown_vendor.cfg").read_text())
    line = UNKNOWN_TEACH["MGMT-006"]
    options = client.get(f"/api/adaptive/scans/{scan['scan_id']}/meanings",
                         params={"control_id": "MGMT-006", "line_number": line}).json()["options"]
    assert options, "the page offers no answer for this line"
    body = {"control_id": "MGMT-006", "line_number": line,
            "predicate": options[0]["predicate"], "asserted_value": options[0].get("value"),
            "subject": options[0].get("subject")}
    draft = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers/draft", json=body).json()
    assert draft["errors"] == [] and "{duration:min}" in draft["draft"]["command_pattern"]
    assert client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers", json=body).status_code == 200


def test_unknown_vendor_is_taught_then_fixed(seeded_adaptive_db):
    client = TestClient(app)
    text = (DEMO / "unknown_vendor.cfg").read_text()
    first = _scan(client, "unknown_vendor.cfg", text)
    assert first["posture"] is None  # nothing decided yet: suspected problems are never scored
    for control, line in UNKNOWN_TEACH.items():
        saved = client.post(f"/api/adaptive/scans/{first['scan_id']}/recognizers",
                            json={"control_id": control, "line_number": line})
        assert saved.status_code == 200, saved.text
    taught = _scan(client, "unknown_vendor.cfg", text)
    assert (taught["posture"], taught["total_findings"]) == (0, 3)
    _confirm_commands(client, taught, UNKNOWN_COMMANDS)
    after = _rescan_corrected(client, taught, "unknown_vendor.cfg")
    assert (after["posture"], after["total_findings"]) == (100, 0)
