"""
Phase 6 -recognizers: confirm a provisional result once, decided decisively on every later scan, no AI.
"""

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.adaptive.capture import capture_unrecognized_lines
from app.adaptive.matcher import EXTRACTION_RECOGNIZER
from app.adaptive.service import AdaptiveService
from app.controls.evaluate import evaluate_controls
from app.db.database import MIGRATIONS
from app.db.mappings import LearnedMapping, MappingConflictError, MappingRepository, MappingValidationError
from app.facts.predicates import IDLE_TIMEOUT, PROTOCOL_ENABLED
from app.facts.recognizers import dialect_fingerprint
from app.main import app
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Status

REPO = Path(__file__).resolve().parents[2]
UNKNOWN_CFG = (REPO / "sample" / "unknown.cfg").read_text(encoding="utf-8")


def _scan(client: TestClient, text: str) -> dict:
    interpreter = MagicMock(side_effect=AssertionError("AI must not be called"))
    with patch("app.api.routes.scan.interpret_lines", interpreter), \
         patch("app.api.routes.scan.is_available", return_value=False):
        resp = client.post("/api/scan", files=[("files", ("unknown.cfg", text.encode(), "text/plain"))])
    assert resp.status_code == 200, resp.text
    interpreter.assert_not_called()
    return resp.json()


def _result(scan: dict, control_id: str) -> dict:
    return next(r for r in scan["results"] if r["control_id"] == control_id)


def _verdict(result: dict) -> tuple:
    return result["status"], result["assurance"], sorted(result["evidence"]["line_numbers"])


def _unknown(text: str) -> NormalizedConfig:
    return NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="u"),
                            raw_config=text, raw_lines=text.splitlines())


def _recognizer(**overrides) -> LearnedMapping:
    values = dict(
        concept="Telnet", normalized_field="", extraction_method=EXTRACTION_RECOGNIZER, confirmed=True,
        predicate=PROTOCOL_ENABLED, subject="telnet", command_pattern="remote-console protocol {enum:protocol}",
        constant_value='{"telnet": true, "*": false}', example_line="remote-console protocol telnet",
    )
    values.update(overrides)
    return LearnedMapping(**values)


def _control(config: NormalizedConfig, control_id: str):
    return next(r for r in evaluate_controls(config) if r.control_id == control_id)


# ── the demo loop ───────────────────────────────────────────────────────────

def test_confirm_telnet_then_rescan_is_decisive_with_zero_ai_calls():
    client = TestClient(app)
    first = _scan(client, UNKNOWN_CFG)
    scan_id = first["scan_id"]
    assert _verdict(_result(first, "MGMT-001")) == ("fail", "heuristic", [70, 71])

    queue = client.get(f"/api/adaptive/scans/{scan_id}/provisional").json()["items"]
    telnet = next(i for i in queue if i["control_id"] == "MGMT-001")
    assert [(line["line_number"], line["value"]) for line in telnet["lines"]] == [(71, True)]

    body = {"control_id": "MGMT-001", "line_number": 71}
    draft = client.post(f"/api/adaptive/scans/{scan_id}/recognizers/draft", json=body).json()
    assert draft["errors"] == []
    assert draft["draft"]["command_pattern"] == "remote-console protocol {enum:protocol}"
    assert json.loads(draft["draft"]["value"]) == {"telnet": True, "*": False}
    # replay covers every stored scan (other tests' too); this scan's change must be among them
    assert ("MGMT-001", "fail (heuristic)", "fail (confirmed)") in {
        (c["control_id"], c["before"], c["after"]) for c in draft["replay"]}

    saved = client.post(f"/api/adaptive/scans/{scan_id}/recognizers", json=body)
    assert saved.status_code == 200, saved.text
    assert _verdict(_result(saved.json()["scan"], "MGMT-001")) == ("fail", "confirmed", [70, 71])

    rescan = _scan(client, UNKNOWN_CFG)
    assert _verdict(_result(rescan, "MGMT-001")) == ("fail", "confirmed", [70, 71])
    assert first["coverage"] == 0 and rescan["coverage"] > 0 and rescan["posture"] == 0
    rescan_queue = client.get(f"/api/adaptive/scans/{rescan['scan_id']}/provisional").json()["items"]
    assert "MGMT-001" not in {i["control_id"] for i in rescan_queue}


def test_same_recognizer_on_another_protocol_passes_the_telnet_control():
    MappingRepository().save_mapping(_recognizer(dialect_fingerprint=dialect_fingerprint(UNKNOWN_CFG.splitlines())))
    ssh = UNKNOWN_CFG.replace("remote-console protocol telnet", "remote-console protocol ssh")
    assert _verdict(_result(_scan(TestClient(app), ssh), "MGMT-001")) == ("pass", "confirmed", [70, 71])


def test_admin_picks_a_unit_for_an_unstated_duration():
    client = TestClient(app)
    scan_id = _scan(client, UNKNOWN_CFG)["scan_id"]
    body = {"control_id": "MGMT-006", "line_number": 38}
    draft = client.post(f"/api/adaptive/scans/{scan_id}/recognizers/draft", json=body).json()
    assert "unit" in draft["errors"][0]
    assert client.post(f"/api/adaptive/scans/{scan_id}/recognizers", json=body).status_code == 422

    body["command_pattern"] = "operator inactivity-lock {duration:s}"
    saved = client.post(f"/api/adaptive/scans/{scan_id}/recognizers", json=body)
    assert saved.status_code == 200, saved.text
    result = _result(saved.json()["scan"], "MGMT-006")
    assert (result["assurance"], result["evidence"]["line_numbers"]) == ("confirmed", [38])


def test_rejecting_a_provisional_line_removes_the_heuristic():
    client = TestClient(app)
    scan_id = _scan(client, UNKNOWN_CFG)["scan_id"]
    resp = client.post(f"/api/adaptive/scans/{scan_id}/provisional/reject",
                       json={"control_id": "MGMT-001", "line_number": 71})
    assert resp.status_code == 200, resp.text
    assert _result(resp.json(), "MGMT-001")["status"] == "not_configured"
    assert _result(_scan(client, UNKNOWN_CFG), "MGMT-001")["status"] == "not_configured"


def test_confirmed_vendor_configs_are_not_recognizer_targets():
    client = TestClient(app)
    cisco = (REPO / "backend" / "tests" / "fixtures" / "cisco_secure.cfg").read_text(encoding="utf-8")
    scan_id = _scan(client, cisco)["scan_id"]
    resp = client.post(f"/api/adaptive/scans/{scan_id}/recognizers/draft", json={"control_id": "MGMT-001", "line_number": 1})
    assert resp.status_code == 422


# ── gates ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("overrides,error", [
    (dict(command_pattern="set {polarity}", constant_value=None, example_line="set enabled"), "keywords"),
    (dict(command_pattern="set telnet {polarity}", constant_value=None, example_line="set telnet enabled"), "keywords"),
    (dict(command_pattern="remote-console protocol telnet", constant_value="true"), "Polarity"),
    (dict(command_pattern="management-plane legacy-access disabled", constant_value="true",
          example_line="management-plane legacy-access disabled"), "contradicts"),
    (dict(constant_value=None), "value table"),
    (dict(command_pattern="remote-console protocol {int}", example_line="remote-console protocol 23"), "on or off"),
    (dict(predicate=IDLE_TIMEOUT, subject=None, command_pattern="operator inactivity-lock {duration}",
          constant_value=None, example_line="operator inactivity-lock 600"), "unit"),
    (dict(command_pattern="remote-console protocol {enum:protocol}", example_line="remote-console mode telnet"), "match"),
])
def test_unsafe_recognizers_are_rejected(overrides, error):
    with pytest.raises(MappingValidationError, match=error):
        MappingRepository().save_mapping(_recognizer(**overrides))
    assert MappingRepository().list_mappings() == []


def test_identical_template_conflicts_with_an_existing_recognizer():
    repo = MappingRepository()
    repo.save_mapping(_recognizer())
    with pytest.raises(MappingConflictError):
        repo.save_mapping(_recognizer(constant_value='{"telnet": false, "*": true}'))


# ── matching ────────────────────────────────────────────────────────────────

def test_conflicting_recognizers_are_unknown():
    repo = MappingRepository()
    repo.save_mapping(_recognizer())
    repo.save_mapping(_recognizer(command_pattern="management-plane legacy-access {polarity}", constant_value=None,
                                  example_line="management-plane legacy-access disabled"))
    result = _control(_unknown(UNKNOWN_CFG), "MGMT-001")
    assert (result.status, result.evidence.line_numbers) == (Status.UNKNOWN, [30, 70, 71])
    assert "Conflicting" in result.reason


def test_dialect_fingerprint_must_overlap_unless_any_dialect():
    other = "hostname edge\nremote-console protocol telnet\nfirewall enable\n"
    MappingRepository().save_mapping(_recognizer(dialect_fingerprint=dialect_fingerprint(UNKNOWN_CFG.splitlines())))
    assert _control(_unknown(other), "MGMT-001").status == Status.NOT_CONFIGURED

    MappingRepository().save_mapping(_recognizer(command_pattern="remote-console   protocol {enum:proto}",
                                                 scope_template=None, dialect_fingerprint=None,
                                                 negatives=["remote-console protocol ssh"]))
    result = _control(_unknown(other), "MGMT-001")
    assert (result.status, result.assurance) == (Status.FAIL, Assurance.CONFIRMED)


def test_negatives_and_disabled_blocks():
    MappingRepository().save_mapping(_recognizer(negatives=["Remote-Console  protocol telnet"]))
    assert _control(_unknown("remote-console protocol telnet\n"), "MGMT-001").status == Status.NOT_CONFIGURED

    repo = MappingRepository()
    repo.save_mapping(_recognizer(command_pattern="console-access protocol {enum:protocol}",
                                  example_line="console-access protocol telnet"))
    result = _control(_unknown("console-access state disabled\nconsole-access protocol telnet\n"), "MGMT-001")
    assert (result.status, result.assurance, result.evidence.line_numbers) == (Status.PASS, Assurance.CONFIRMED, [1, 2])


def test_a_recognizer_never_hides_a_contradicting_heuristic_elsewhere():
    MappingRepository().save_mapping(_recognizer(command_pattern="management-plane legacy-access {polarity}",
                                                 constant_value=None,
                                                 example_line="management-plane legacy-access disabled"))
    result = _control(_unknown(UNKNOWN_CFG), "MGMT-001")
    # line 30 says Telnet off (confirmed), lines 70-71 still suspect it on
    assert result.status == Status.FAIL and result.assurance == Assurance.HEURISTIC


def test_recognized_lines_are_not_sent_to_ai():
    repo = MappingRepository()
    repo.save_mapping(_recognizer())
    config = _unknown("remote-console state enabled\nremote-console protocol telnet\nsecure-shell protocol-version 1\n")
    capture_unrecognized_lines(config)
    interpreter = MagicMock(return_value=[])
    AdaptiveService(repository=repo, interpreter=interpreter, ai_available=lambda: True).process(config)
    sent = [line.line_number for line in interpreter.call_args[0][0]]
    assert 2 not in sent and 3 in sent


def test_v1_database_migrates_and_field_mappings_get_predicates(isolated_adaptive_db):
    conn = sqlite3.connect(isolated_adaptive_db)
    conn.executescript(MIGRATIONS[0])
    conn.execute("PRAGMA user_version = 1")
    conn.execute(
        "INSERT INTO learned_mappings (concept, normalized_field, command_pattern, extraction_method, "
        "expected_value_type, constant_value, confirmed, created_at, updated_at) "
        "VALUES ('telnet', 'management.telnet_enabled', 'remote-console protocol telnet', 'constant', 'bool', 'true', 1, 'x', 'x')"
    )
    conn.commit()
    conn.close()

    [mapping] = MappingRepository().list_mappings()
    assert (mapping.predicate, mapping.subject, mapping.negatives) == (PROTOCOL_ENABLED, "telnet", [])
