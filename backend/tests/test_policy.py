"""Organisation policy (app/controls/policy.py): tightens only, and every result it changed says so."""

import io
import json

import pytest
from fastapi.testclient import TestClient

from app import cli
from app.controls import policy
from app.main import app

CONFIG = """!
hostname POLICY-01
!
logging host 10.9.9.9
!
line vty 0 4
 exec-timeout 12 0
 transport input ssh
!
"""
STRICT = {"name": "Acme baseline", "idle_timeout_minutes": 10, "syslog_servers": ["10.1.1.1"]}


def test_a_policy_can_only_tighten():
    assert policy.parse(STRICT).idle_timeout_minutes == 10
    for bad in ({"name": "x", "idle_timeout_minutes": 30}, {"name": "x", "password_min_length": 6},
                {"name": "x", "login_attempts": 0}, {"idle_timeout_minutes": 10}, {"name": "x", "colour": 1},
                {"name": "x", "ntp_servers": ["10.0.0.1; rm -rf"]}, ["not", "an", "object"]):
        with pytest.raises(ValueError):
            policy.parse(bad)


@pytest.fixture
def client(seeded_adaptive_db):
    return TestClient(app)


def _scan(client, pol=None):
    data = {"policy": json.dumps(pol)} if pol is not None else {}
    return client.post("/api/scan", data=data,
                       files={"files": ("r.cfg", io.BytesIO(CONFIG.encode()), "text/plain")})


def _result(scan, control_id):
    return next(r for r in scan["results"] if r["control_id"] == control_id)


def test_the_policy_changes_verdicts_and_the_results_cite_it(client):
    default = _scan(client).json()
    assert default["policy"] is None
    assert _result(default, "MGMT-006")["status"] == "pass" and _result(default, "LOG-001")["status"] == "pass"

    strict = _scan(client, STRICT).json()
    assert strict["policy"]["name"] == "Acme baseline"
    timeout, log = _result(strict, "MGMT-006"), _result(strict, "LOG-001")
    assert timeout["status"] == "fail" and "organisation policy 'Acme baseline'" in timeout["reason"]
    assert log["status"] == "fail" and "10.9.9.9" in log["reason"]
    assert _result(_scan(client).json(), "MGMT-006")["status"] == "pass"  # nothing leaks into the next scan


def test_a_bad_policy_is_refused_with_the_reason(client):
    response = _scan(client, {"name": "x", "idle_timeout_minutes": 60})
    assert response.status_code == 422 and "tighten" in response.json()["detail"]
    assert client.post("/api/scan", data={"policy": "{not json"},
                       files={"files": ("r.cfg", io.BytesIO(CONFIG.encode()), "text/plain")}).status_code == 422


def test_the_cli_takes_a_policy(tmp_path, monkeypatch, capsys, seeded_adaptive_db):
    monkeypatch.setattr(cli, "isolated_engine", lambda db=None: None)
    cfg, pol = tmp_path / "r.cfg", tmp_path / "policy.json"
    cfg.write_text(CONFIG)
    pol.write_text(json.dumps(STRICT))

    def timeout(*extra):
        cli.main(["scan", str(cfg), "--json", *extra])
        return _result(json.loads(capsys.readouterr().out), "MGMT-006")["status"]

    assert (timeout(), timeout("--policy", str(pol))) == ("pass", "fail")
    pol.write_text('{"name": "loose", "login_attempts": 50}')
    assert cli.main(["scan", str(cfg), "--policy", str(pol)]) == 2
