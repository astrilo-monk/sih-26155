"""
Teaching never turns a line that does not state a setting into a decided PASS.

Two traps found by scanning real-world style files and accepting every line the resolution queue offered:
a Junos local log file (``syslog { file messages { … } }``) drafted as a remote syslog server, and NX-OS
``feature tacacs+`` drafted as central AAA. Both used to save and flip their check to "pass (confirmed)".
"""

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.facts.recognizers import recognizer_facts
from app.main import app

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _scan(client: TestClient, path: Path) -> dict:
    with patch("app.api.routes.scan.is_available", return_value=False):
        response = client.post("/api/scan", files=[("files", (path.name, path.read_bytes(), "text/plain"))])
    assert response.status_code == 200, response.text
    return response.json()


def _status(scan: dict, control_id: str) -> str:
    return next(r["status"] for r in scan["results"] if r["control_id"] == control_id)


@pytest.mark.parametrize("path, control_id, line, predicate, asserted", [
    (FIXTURES / "demo" / "juniper_edge_braces.conf", "LOG-001", 24, "log.remote.destination", None),
    (FIXTURES / "lookalikes" / "cisco_nxos.cfg", "MGMT-008", 5, "auth.central_aaa.enabled", True),
])
def test_a_line_that_does_not_state_the_setting_cannot_be_taught(seeded_adaptive_db, path, control_id, line,
                                                                  predicate, asserted):
    client = TestClient(app)
    scan = _scan(client, path)
    before = _status(scan, control_id)
    body = {"config_index": 0, "control_id": control_id, "line_number": line, "predicate": predicate}
    if asserted is not None:
        body["asserted_value"] = asserted
    draft = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers/draft", json=body).json()
    assert draft["errors"], "the draft must explain why the line cannot be taught"
    saved = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers", json=body)
    assert saved.status_code == 422
    assert _status(_scan(client, path), control_id) == before != "pass"


def test_lines_that_do_state_the_setting_are_still_taught(seeded_adaptive_db):
    client = TestClient(app)
    path = FIXTURES / "lookalikes" / "arista_eos.cfg"
    scan = _scan(client, path)
    body = {"config_index": 0, "control_id": "MGMT-002", "line_number": 51,
            "predicate": "mgmt.remote_access.protocol_enabled", "asserted_value": False}
    saved = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers", json=body)
    assert saved.status_code == 200, saved.text
    assert _status(saved.json()["scan"], "MGMT-002") == "pass"


@pytest.mark.parametrize("text, expected", [
    ("syslog {\n    host loghost;\n}", [["loghost"]]),          # a bare name where the line says "host"
    ("info-center loghost logsrv", [["logsrv"]]),
    ("logging host 192.0.2.50", [["192.0.2.50"]]),
    ("syslog {\n    file messages {\n        any notice;\n    }\n}", []),   # a local file is not a server
])
def test_a_bare_word_is_a_host_only_where_the_line_says_so(seeded_adaptive_db, text, expected):
    assert [f.value for f in recognizer_facts(text.splitlines())[0] if f.predicate == "log.remote.destination"] \
        == expected
