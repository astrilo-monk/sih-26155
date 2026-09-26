"""The final review: verified fixes plus the candidates you confirmed, rescanned once, then downloaded."""

import pathlib
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.main import app

PAN = (pathlib.Path(__file__).parents[2] / "demo-sih" / "paloalto_fw_vulnerable.cfg").read_text(encoding="utf-8")


def _scan(client):
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        response = client.post("/api/scan", files=[("files", ("pan.cfg", PAN.encode(), "text/plain"))])
    assert response.status_code == 200, response.text
    return response.json()


def test_confirmed_removals_and_manual_commands_in_the_final_review(seeded_adaptive_db):
    client = TestClient(app)
    scan = _scan(client)
    body = {"scan_id": scan["scan_id"], "device_hostname": scan["devices"][0]["hostname"], "config_index": 0}
    inputs = {"management_subnet": "10.50.0.0/24"}

    first = client.post("/api/remediation/final", json={"scan_id": scan["scan_id"], "inputs": inputs}).json()
    device = first["devices"][0]
    assert device["changed"] and "MGMT-004" not in device["included"] and device["by_hand"] == []

    # a verified removal you confirm joins the file; a command it cannot simulate is listed, never written
    removal = {**body, "rule_id": "MGMT-004"}
    assert client.post("/api/remediation/candidate/derive", json=removal).json()["status"] == "verified"
    assert client.post("/api/remediation/candidate/confirm", json=removal).status_code == 200
    manual = {**body, "rule_id": "LOG-002", "command": "set ntp authentication-key 1 sha256"}
    assert client.post("/api/remediation/candidate", json=manual).status_code == 200
    assert client.post("/api/remediation/candidate/verify", json=manual).json()["status"] == "unverified"
    assert client.post("/api/remediation/candidate/confirm", json=manual).status_code == 200

    final = client.post("/api/remediation/final", json={"scan_id": scan["scan_id"], "inputs": inputs}).json()
    device = final["devices"][0]
    assert "MGMT-004" in device["included"]
    assert [h["control_id"] for h in device["by_hand"]] == ["LOG-002"]
    assert device["after"]["posture"] > first["devices"][0]["after"]["posture"]

    text = client.post("/api/download-fixed", json={"scan_id": scan["scan_id"], "inputs": inputs,
                                                    "include_confirmed": True}).text
    assert "snmp-community-string" not in text and "ntp authentication-key" not in text
    assert "permitted-ip 10.50.0.0/24" in text
    # the default download is unchanged: only what the rescan proved secure
    plain = client.post("/api/download-fixed", json={"scan_id": scan["scan_id"], "inputs": inputs}).text
    assert "snmp-community-string" in plain


def test_one_devices_answer_never_fills_in_another(seeded_adaptive_db):
    ios = (pathlib.Path(__file__).parents[2] / "demo-sih" / "cisco_edge_vulnerable.cfg").read_text(encoding="utf-8")
    client = TestClient(app)
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        scan = client.post("/api/scan", files=[("files", ("a.cfg", ios.encode(), "text/plain")),
                                               ("files", ("b.cfg", ios.encode(), "text/plain"))]).json()
    subnet = {"management_subnet": "10.50.0.0/24"}
    devices = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"],
                                                          "device_inputs": {"0": subnet}}).json()["devices"]
    status = [{r["rule_id"]: r["status"] for r in d["remediations"]}["MGMT-003"] for d in devices]
    assert status == ["fixed", "needs_input"]


def test_ask_ai_for_one_check_keeps_only_that_checks_suggestions(seeded_adaptive_db):
    client = TestClient(app)
    scan = _scan(client)
    url = f"/api/adaptive/scans/{scan['scan_id']}/ask-ai"
    body = {"config_index": 0, "control_id": "MGMT-008"}
    with patch("app.ai.client.is_available", return_value=False):
        assert client.post(url, json=body).status_code == 503

    def judge(config, results, budget):
        assert [r.control_id for r in results] == ["MGMT-008"] and budget.remaining == 1
        config.ai_facts = []
        config.ai_notes["MGMT-008"] = "the AI proposed no fact with a verifiable citation"

    with patch("app.ai.client.is_available", return_value=True), patch("app.ai.judge.judge_config", judge):
        answer = client.post(url, json=body).json()
    assert answer == {"found": False, "note": "the AI proposed no fact with a verifiable citation"}
    # a decided check is refused
    decided = client.post(url, json={"config_index": 0, "control_id": "MGMT-001"})
    assert decided.status_code in (409, 503)
