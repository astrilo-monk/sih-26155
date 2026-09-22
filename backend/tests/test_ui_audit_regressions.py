"""
Regressions from the browser UI audit.

* No configuration secret reaches an API response the browser renders (scan, frameworks,
  remediation, review, recognizer drafts); /download-fixed alone returns the real file.
* ``config_index`` identifies a device: two uploads with the same hostname never cross-target.
* Generic configurations report the hostname they state, never a guess.
* A manual-review remediation does not describe a change it did not make.
* CIS 1.3.3 (banner motd) is not claimed by a control that cannot tell motd from login banners.
"""

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.facts.heuristics import generic_hostname
from app.main import app

REPO = Path(__file__).resolve().parents[2]
SAMPLES = REPO / "sample"
FIXTURES = Path(__file__).parent / "fixtures"

CISCO_SECRETS = ("FakePw-Admin-111", "FakeEnable-222", "FakeLine-333", "FakeComm-444")
UNKNOWN_SECRETS = ("FakeCred-666", "FakeCommunity-777", "FakeRadius-888")
NTP_KEY = "FakeNtpKey-555"
INPUTS = {"syslog_server": "10.20.0.5", "ntp_server": "10.20.0.6", "ntp_key_id": "7", "ntp_key": NTP_KEY,
          "management_subnet": "10.0.0.0/24"}

UNKNOWN_WITH_SECRETS = """system-name EDGE-LAB-01
remote-console state enabled
remote-console protocol telnet
admin-user root credential FakeCred-666
snmp-agent community-string FakeCommunity-777 read-write
identity-services centralized-authentication enabled
radius-peer 10.1.1.5 shared-key FakeRadius-888
remote-logging disabled
"""


def _cisco_with_secrets() -> str:
    text = (SAMPLES / "cisco" / "01_cisco_multi_vulnerability.cfg").read_text()
    for old, new in (("password 0 password123", "password 0 FakePw-Admin-111"),
                     ("enable password password123", "enable password FakeEnable-222"),
                     (" password cisco", " password FakeLine-333"),
                     ("snmp-server community private RW", "snmp-server community FakeComm-444 RW")):
        assert old in text, old
        text = text.replace(old, new)
    return text


@pytest.fixture
def client():
    return TestClient(app)


def _scan(client, *files) -> dict:
    no_ai = MagicMock(side_effect=AssertionError("these scans must not call the AI"))
    with patch("app.api.routes.scan.interpret_lines", no_ai), \
         patch("app.api.routes.scan.is_available", return_value=False):
        resp = client.post("/api/scan", files=[("files", (name, text.encode(), "text/plain")) for name, text in files])
    assert resp.status_code == 200, resp.text
    return resp.json()


def _assert_no_secret(text: str, secrets) -> None:
    leaked = [s for s in secrets if s in text]
    assert not leaked, f"secrets in API response: {leaked}"


# ── D1: secrets ──────────────────────────────────────────────────────────────

def test_scan_response_redacts_every_secret_but_keeps_the_evidence(client):
    data = _scan(client, ("cisco.cfg", _cisco_with_secrets()), ("unknown.cfg", UNKNOWN_WITH_SECRETS))
    body = json.dumps(data)

    _assert_no_secret(body, CISCO_SECRETS + UNKNOWN_SECRETS)
    weak_passwords = [f for f in data["findings"] if f["rule_id"] == "MGMT-005" and f["evidence_lines"]]
    assert weak_passwords, "the weak-password finding keeps its evidence"
    assert any("<SECRET:" in line for f in weak_passwords for line in f["evidence_lines"])
    assert all(f["line_numbers"] for f in weak_passwords)
    framework_lines = [line for view in data["frameworks"] for req in view["requirements"]
                       for c in req["controls"] for line in c["evidence"]["lines"]]
    assert any("<SECRET:" in line for line in framework_lines)


def test_one_configs_weak_secret_never_blanks_words_in_another_config(client):
    cisco = (SAMPLES / "cisco" / "01_cisco_multi_vulnerability.cfg").read_text()
    assert " password console" in cisco  # a password that is also a common configuration word
    unknown = UNKNOWN_WITH_SECRETS
    data = _scan(client, ("cisco.cfg", cisco), ("unknown.cfg", unknown))

    telnet = next(f for f in data["findings"] if f["config_index"] == 1 and f["rule_id"] == "MGMT-001")
    assert any("remote-console protocol telnet" in line for line in telnet["evidence_lines"]), telnet["evidence_lines"]
    assert "password console" not in json.dumps(data)


def test_remediation_views_are_redacted_and_only_the_download_is_real(client):
    data = _scan(client, ("cisco.cfg", _cisco_with_secrets()))
    scan_id = data["scan_id"]

    plan = client.post("/api/remediation/plan", json={"scan_id": scan_id, "inputs": INPUTS})
    assert plan.status_code == 200, plan.text
    _assert_no_secret(plan.text, CISCO_SECRETS + (NTP_KEY,))
    device = plan.json()["devices"][0]
    assert device["fixed_config"] and "<SECRET:" in device["fixed_config"]
    assert "LOG-002" in device["fixed_controls"]

    for rule in ("LOG-002", "MGMT-005", "MGMT-004"):
        one = client.post("/api/remediate", json={"scan_id": scan_id, "rule_id": rule, "device_hostname": "DMZ-EDGE-10",
                                                  "config_index": 0, "inputs": INPUTS})
        assert one.status_code == 200, one.text
        _assert_no_secret(one.text, CISCO_SECRETS + (NTP_KEY,))

    download = client.post("/api/download-fixed", json={"scan_id": scan_id, "inputs": INPUTS})
    assert download.status_code == 200
    assert NTP_KEY in download.text, "the downloaded configuration is the real, deployable file"


def test_review_surfaces_are_redacted(client):
    data = _scan(client, ("unknown.cfg", UNKNOWN_WITH_SECRETS))
    scan_id = data["scan_id"]
    for path in (f"/api/adaptive/scans/{scan_id}/provisional", f"/api/adaptive/scans/{scan_id}/review?include_resolved=true"):
        resp = client.get(path)
        assert resp.status_code == 200, resp.text
        _assert_no_secret(resp.text, UNKNOWN_SECRETS)


def test_recognizer_is_never_drafted_from_a_secret_line(client, isolated_adaptive_db):
    data = _scan(client, ("unknown.cfg", UNKNOWN_WITH_SECRETS))
    scan_id = data["scan_id"]
    items = client.get(f"/api/adaptive/scans/{scan_id}/provisional").json()["items"]
    target = next(((item, line) for item in items for line in item["lines"] if line["line_number"] == 7), None)
    assert target, f"the radius line should be a provisional AAA statement: {items}"
    item, line = target
    body = {"config_index": item["config_index"], "control_id": item["control_id"], "line_number": 7}

    draft = client.post(f"/api/adaptive/scans/{scan_id}/recognizers/draft", json=body)
    assert draft.status_code == 200, draft.text
    assert any("secret" in e for e in draft.json()["errors"])
    _assert_no_secret(draft.text, UNKNOWN_SECRETS)
    assert client.post(f"/api/adaptive/scans/{scan_id}/recognizers", json=body).status_code == 422


# ── B1: config_index is the device identity ─────────────────────────────────

def test_duplicate_hostnames_never_cross_target_remediation(client):
    secure = (SAMPLES / "frontinet" / "05_fortigate_secure.cfg").read_text()
    vulnerable = (SAMPLES / "frontinet" / "04_fortigate_vulnerable.cfg").read_text()
    data = _scan(client, ("secure.cfg", secure), ("vulnerable.cfg", vulnerable))
    assert [d["hostname"] for d in data["devices"]] == ["BRANCH-FGT-02", "BRANCH-FGT-02"]

    telnet = [f for f in data["findings"] if f["rule_id"] == "MGMT-001"]
    assert telnet and {f["config_index"] for f in telnet} == {1}

    def remediate(**extra):
        return client.post("/api/remediate", json={"scan_id": data["scan_id"], "rule_id": "MGMT-001",
                                                   "device_hostname": "BRANCH-FGT-02", **extra})

    selected = remediate(config_index=1)
    assert selected.status_code == 200 and selected.json()["config_index"] == 1
    assert selected.json()["status"] == "fixed", selected.json()["reason"]
    assert remediate(config_index=0).json()["status"] == "not_failing"
    ambiguous = remediate()
    assert ambiguous.status_code == 409 and "config_index" in ambiguous.text


# ── B8: generic hostname ────────────────────────────────────────────────────

@pytest.mark.parametrize("lines, expected", [
    (["set deviceconfig setting management hostname PA-EDGE-01"], "PA-EDGE-01"),
    (["system-name CORE-GATE-07"], "CORE-GATE-07"),
    (["system {", "    host-name J-EDGE;", "}"], "J-EDGE"),
    (["config system global", '    set hostname "FW-01"', "end"], "FW-01"),
    (["# hostname COMMENTED-OUT"], None),
    (["interface eth0", " description hostname NOT-A-NAME"], None),
    (["no hostname"], None),
    (["hostname A-ONE", "hostname B-TWO"], None),
    (["logging host 10.1.1.1"], None),
])
def test_generic_hostname(lines, expected):
    assert generic_hostname(lines) == expected


def test_generic_and_unverified_configs_report_their_stated_hostname(client):
    mixed = (FIXTURES / "lookalikes" / "mixed_ios_foreign_block.cfg").read_text()
    (mixed_name,) = set(re.findall(r"^hostname (\S+)", mixed, re.M))
    data = _scan(client, ("pa.cfg", (SAMPLES / "paloalto.cfg").read_text()),
                 ("unknown.cfg", (SAMPLES / "unknown.cfg").read_text()), ("mixed.cfg", mixed))
    assert [d["hostname"] for d in data["devices"]] == ["PA-EDGE-01", "CORE-GATE-07", mixed_name]
    assert [d["vendor"] for d in data["devices"]] == ["unknown", "unknown", "unknown"]


# ── E5 / E6 ─────────────────────────────────────────────────────────────────

def test_manual_review_remediation_describes_no_change(client):
    data = _scan(client, ("cisco.cfg", (SAMPLES / "cisco" / "01_cisco_multi_vulnerability.cfg").read_text()))
    plan = client.post("/api/remediation/plan", json={"scan_id": data["scan_id"], "inputs": {}}).json()
    weak = next(r for r in plan["devices"][0]["remediations"] if r["rule_id"] == "MGMT-005")
    assert weak["status"] == "manual_review"
    assert weak["diff"] == "" and weak["explanation"] == "" and weak["fixed_config"] is None


def test_cis_motd_banner_is_not_claimed(client):
    data = _scan(client, ("cisco.cfg", (SAMPLES / "cisco" / "01_cisco_multi_vulnerability.cfg").read_text()))
    requirements = {r["requirement_id"] for v in data["frameworks"] if v["framework"] == "CIS" for r in v["requirements"]}
    assert "1.3.2" in requirements and "1.3.3" not in requirements


def test_scan_status_reports_whether_the_backend_holds_a_scan(client):
    data = _scan(client, ("unknown.cfg", UNKNOWN_WITH_SECRETS))
    assert client.get(f"/api/scan/{data['scan_id']}/status").json() == {"scan_id": data["scan_id"], "held": True, "archived": False}
    gone = client.get("/api/scan/no-such-scan/status")
    assert gone.status_code == 200 and gone.json() == {"scan_id": "no-such-scan", "held": False, "archived": False}
