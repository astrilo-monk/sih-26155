"""
The per-device compliance report (PDF).

The report restates what a scan already decided. These tests hold it to the same rules as the rest
of the product: no secret ever reaches it, nothing the configuration does not state is reported
(serial numbers, hardware), provisional readings are never presented as compliance, and no vendor
command is shown for a vendor that was not confirmed.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.routes.report import _filename
from app.main import app
from app.reporting.report import report_blocks, report_text

# The Junos configuration these tests are pinned to lives in tests/fixtures/: sample/ is the user's
# playground and its files change, while every number asserted here is a reading of one exact file.
JUNIPER_CFG = Path(__file__).resolve().parent / "fixtures" / "juniper_edge.cfg"

CISCO_WITH_SECRETS = """!
hostname EDGE-TEST-01
!
enable password 0 SuperSecretEnable123
username admin privilege 15 password 0 AdminPassw0rdVal
snmp-server community TopSecretCommunity RW
!
line vty 0 4
 password 0 VtyLinePass99
 transport input telnet ssh
 exec-timeout 0 0
!
ip http server
no ip http secure-server
!
"""
SECRETS = ("SuperSecretEnable123", "AdminPassw0rdVal", "TopSecretCommunity", "VtyLinePass99")

PROSE = "Meeting notes\n\nWe discussed the roadmap and agreed to revisit it next week.\n"


@pytest.fixture
def client(seeded_adaptive_db):
    return TestClient(app)


def upload(client, name: str, text: str) -> str:
    response = client.post("/api/scan", files={"files": (name, io.BytesIO(text.encode()), "text/plain")})
    assert response.status_code == 200, response.text
    return response.json()["scan_id"]


def report(client, scan_id: str, **body):
    response = client.post("/api/report", json={"scan_id": scan_id, **body})
    assert response.status_code == 200, response.text
    return response


def text_of(client, scan_id: str, index: int = 0) -> str:
    """The report's document model as text -what the PDF lays out."""
    from app.api.routes.remediation import _device_plan, _stored
    from app.api.routes.scan import build_scan_response

    stored = _stored(scan_id)
    return report_text(report_blocks(build_scan_response(scan_id), index, _device_plan(stored, index, {})))


# ── the file that is produced ────────────────────────────────────────────────

def test_one_device_returns_a_pdf_named_after_it(client):
    scan_id = upload(client, "cisco.cfg", CISCO_WITH_SECRETS)
    response = report(client, scan_id)
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")
    assert "EDGE-TEST-01_compliance_report.pdf" in response.headers["content-disposition"]


def test_several_devices_return_one_pdf_each(client):
    response = client.post("/api/scan", files=[
        ("files", ("a.cfg", io.BytesIO(CISCO_WITH_SECRETS.encode()), "text/plain")),
        ("files", ("b.cfg", io.BytesIO(JUNIPER_CFG.read_bytes()), "text/plain")),
    ])
    assert response.status_code == 200, response.text
    scan_id = response.json()["scan_id"]

    archive = zipfile.ZipFile(io.BytesIO(report(client, scan_id).content))
    names = archive.namelist()
    assert len(names) == 2 and all(n.endswith(".pdf") for n in names)
    assert all(archive.read(n).startswith(b"%PDF-") for n in names)
    # one device on its own is still a single PDF
    assert report(client, scan_id, config_index=1).content.startswith(b"%PDF-")


def test_a_hostname_cannot_escape_the_download_name():
    assert _filename("../../etc/passwd") == ".._.._etc_passwd_compliance_report.pdf"
    assert _filename("") == "device_compliance_report.pdf"


def test_an_unknown_scan_or_device_is_not_invented(client):
    assert client.post("/api/report", json={"scan_id": "no-such-scan"}).status_code == 404
    scan_id = upload(client, "cisco.cfg", CISCO_WITH_SECRETS)
    assert client.post("/api/report", json={"scan_id": scan_id, "config_index": 7}).status_code == 404


# ── what the report may and may not say ──────────────────────────────────────

def test_no_secret_of_the_configuration_reaches_the_report(client):
    scan_id = upload(client, "cisco.cfg", CISCO_WITH_SECRETS)
    body = text_of(client, scan_id)
    for secret in SECRETS:
        assert secret not in body, f"the report leaked {secret!r}"
    pdf = report(client, scan_id).content
    for secret in SECRETS:
        assert secret.encode() not in pdf, f"the rendered PDF leaked {secret!r}"
    # the finding is still reported, with its evidence
    assert "MGMT-004" in body and "SECRET" in body


def test_serial_numbers_and_hardware_are_not_invented(client):
    body = text_of(client, upload(client, "cisco.cfg", CISCO_WITH_SECRETS))
    assert "Serial number and chassis details are not part of a device configuration" in body
    assert "EDGE-TEST-01" in body


def test_findings_state_how_each_result_was_established(client):
    body = text_of(client, upload(client, "cisco.cfg", CISCO_WITH_SECRETS))
    assert "MGMT-001" in body and "FAIL" in body
    assert "dedicated parser" in body
    assert "PASS and FAIL are reported only from decisive evidence" in body


def test_provisional_readings_are_never_presented_as_compliance(client):
    """An unconfirmed vendor's heuristic readings appear as provisional, never as PASS or FAIL."""
    body = text_of(client, upload(client, "juniper.cfg", JUNIPER_CFG.read_text(encoding="utf-8")))
    assert "provisional" in body
    for line in body.split("\n"):
        if "heuristic reading (provisional)" in line:
            assert " | PASS |" not in line and " | FAIL |" not in line


def test_an_unconfirmed_vendor_gets_no_vendor_commands(client):
    body = text_of(client, upload(client, "juniper.cfg", JUNIPER_CFG.read_text(encoding="utf-8")))
    assert "generates no vendor commands for it" in body
    assert "Configuration change" not in body


def test_a_confirmed_vendor_gets_the_deterministic_change_and_its_verification(client):
    body = text_of(client, upload(client, "cisco.cfg", CISCO_WITH_SECRETS))
    assert "Configuration change" in body
    assert "transport input ssh" in body
    assert "Deterministic fix generated and verified by rescan" in body
    assert "PASSED -" in body


def test_frameworks_are_reported_and_the_unmapped_ones_are_named(client):
    body = text_of(client, upload(client, "cisco.cfg", CISCO_WITH_SECRETS))
    assert "NIST SP 800-53 -SP 800-53 Rev. 5" in body
    assert "Not mapped and not claimed" in body
    assert "DISA STIG -Network Device Management SRG" in body
    assert "ISO/IEC 27001 -ISO/IEC 27001:2022 Annex A" in body
    assert "CIS Controls v8" in body
    assert "is not a certification" in body


def test_undecided_checks_are_listed_with_what_they_need(client):
    body = text_of(client, upload(client, "juniper.cfg", JUNIPER_CFG.read_text(encoding="utf-8")))
    assert "Checks that need administrator input" in body
    assert "NOT CONFIGURED" in body or "UNKNOWN" in body
    assert "These are not failures and not passes" in body


def test_coverage_is_stated_next_to_the_posture(client):
    body = text_of(client, upload(client, "juniper.cfg", JUNIPER_CFG.read_text(encoding="utf-8")))
    assert "% of applicable controls decided from evidence" in body
    assert "The posture covers only the" in body


def test_a_file_without_configuration_is_reported_unreadable_and_unscored(client):
    body = text_of(client, upload(client, "notes.txt", PROSE))
    assert "does not contain enough recognizable configuration to assess" in body
    assert "not assessed -no control could be decided from validated evidence" in body
