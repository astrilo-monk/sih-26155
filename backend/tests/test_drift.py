"""Changes since the last audit (app/analysis/drift.py): only decided verdicts move, and losing evidence is not a fix."""

import io

import pytest
from fastapi.testclient import TestClient

from app.analysis.drift import device_drift, scan_drift
from app.main import app


def _r(cid, status, assurance="parser"):
    return {"config_index": 0, "control_id": cid, "title": cid, "severity": "high", "status": status,
            "assurance": assurance}


def _scan(scan_id, results, host="r1", paths=()):
    return {"scan_id": scan_id, "timestamp": scan_id, "devices": [{"hostname": host, "vendor": "cisco_ios"}],
            "results": results, "attack_paths": [{"config_index": 0, "path_id": p, "title": p} for p in paths]}


def test_fixed_new_and_no_longer_decided_are_kept_apart():
    old = _scan("a", [_r("A", "fail"), _r("B", "pass"), _r("C", "fail"), _r("D", "fail", "heuristic")],
                paths=["takeover"])
    new = _scan("b", [_r("A", "pass"), _r("B", "fail"), _r("C", "unknown", None), _r("D", "pass")])
    d = device_drift(old, 0, new, 0)
    assert [x["control_id"] for x in d["fixed"]] == ["A"]
    assert [x["control_id"] for x in d["new_problems"]] == ["B"]
    assert [x["control_id"] for x in d["no_longer_decided"]] == ["C"]  # evidence lost, not fixed
    assert d["paths_closed"] == ["takeover"] and d["paths_opened"] == []


def test_matches_the_most_recent_scan_of_the_same_device_only():
    new = _scan("c", [_r("A", "pass")])
    earlier = [_scan("b", [_r("A", "pass")], host="other"), _scan("a2", [_r("A", "fail")]), _scan("a1", [])]
    assert [d["previous_scan_id"] for d in scan_drift(new, earlier)] == ["a2"]
    assert scan_drift(new, [_scan("x", [], host="other")]) == []


VULNERABLE = "!\nhostname DRIFT-01\n!\nline vty 0 4\n transport input telnet ssh\n!\n"
FIXED = "!\nhostname DRIFT-01\n!\nline vty 0 4\n transport input ssh\n!\n"


@pytest.fixture
def client(seeded_adaptive_db):
    return TestClient(app)


def _upload(client, text):
    response = client.post("/api/scan", files={"files": ("r.cfg", io.BytesIO(text.encode()), "text/plain")})
    assert response.status_code == 200, response.text
    return response.json()["scan_id"]


def test_rescanning_a_fixed_device_reports_the_fix(client):
    first = _upload(client, VULNERABLE)
    assert client.get(f"/api/scan/{first}/drift").json()["devices"] == []  # first time this device is seen

    second = _upload(client, FIXED)
    [device] = client.get(f"/api/scan/{second}/drift").json()["devices"]
    assert device["previous_scan_id"] == first and device["hostname"] == "DRIFT-01"
    assert "MGMT-001" in [x["control_id"] for x in device["fixed"]]
    assert client.get("/api/scan/nope/drift").status_code == 404
