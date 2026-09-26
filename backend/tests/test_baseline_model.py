"""The Security Baseline Model: every configuration, whatever its vendor, normalized into the same fields."""

import json
import pathlib
import re
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.main import app

ROOT = pathlib.Path(__file__).parents[2]
CISCO = (ROOT / "demo-sih" / "cisco_edge_vulnerable.cfg").read_text(encoding="utf-8")
JUNOS = (ROOT / "teach" / "juniper_junos_5_configs" / "juniper_01_secure.conf").read_text(encoding="utf-8")


def _baseline(client, name, text):
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        scan = client.post("/api/scan", files=[("files", (name, text.encode(), "text/plain"))]).json()
    response = client.get(f"/api/scan/{scan['scan_id']}/baseline", params={"config_index": 0})
    assert response.status_code == 200, response.text
    return response.json()


def _value(baseline, field, subject=None):
    [value] = [s["value"] for s in baseline["settings"] if s["field"] == field and s["subject"] == subject]
    return value


def test_two_vendors_land_in_the_same_fields(seeded_adaptive_db):
    client = TestClient(app)
    cisco, junos = _baseline(client, "c.cfg", CISCO), _baseline(client, "j.conf", JUNOS)
    assert (cisco["device"]["vendor"], junos["device"]["vendor"]) == ("cisco_ios", "unknown")
    assert (_value(cisco, "mgmt.ssh.version"), _value(junos, "mgmt.ssh.version")) == (1, 2)
    assert _value(cisco, "mgmt.remote_access.protocol_enabled", "telnet") is True
    assert _value(junos, "mgmt.remote_access.protocol_enabled", "telnet") is True
    assert _value(junos, "log.remote.destination") == ["192.0.2.60", "192.0.2.61"]
    assert _value(junos, "auth.central_aaa.enabled") == "not_set"
    ssh = next(s for s in junos["settings"] if s["field"] == "mgmt.ssh.version")
    assert ssh["assurance"] == "confirmed" and ssh["lines"] == [{"number": 6, "text": "            protocol-version v2;"}]
    # one fixed schema: every field is either stated or listed as not stated, and says which checks read it
    assert {s["field"] for s in junos["settings"]} | set(junos["not_stated"]) == set(junos["read_by"])
    assert junos["read_by"]["mgmt.ssh.version"] == ["MGMT-007"]


def test_no_secret_leaves_in_a_value_or_a_line(seeded_adaptive_db):
    baseline = json.dumps(_baseline(TestClient(app), "c.cfg", CISCO))
    communities = re.findall(r"^snmp-server community (\S+)", CISCO, re.MULTILINE)
    secrets = ["Cisco@123", "0822455D0A16", "NtpKey2026"]
    assert communities and all(secret in CISCO for secret in secrets)
    for secret in communities + secrets:
        assert secret not in baseline


def test_an_archived_scan_explains_there_is_no_configuration():
    with patch("app.api.routes.scan.load_scan", return_value={"scan_id": "old"}):
        assert TestClient(app).get("/api/scan/old/baseline").status_code == 409
