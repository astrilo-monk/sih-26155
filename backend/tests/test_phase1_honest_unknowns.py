"""
Phase 1c — missing data on an unidentified vendor is never a FAIL or a score.

For a confirmed vendor, an empty field means the parser read the config and
the setting is absent. For an unknown vendor it only means nothing was
interpreted, so absence-based rules stay silent and a config with no
evaluated evidence is "not assessed" instead of 100/100.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.analysis.engine import analyze, analyze_multiple
from app.api.routes.scan import get_scan_store
from app.db.mappings import LearnedMapping, MappingRepository
from app.main import app
from app.models.findings import Finding, Severity
from app.models.normalized import AIFieldMapping, DeviceInfo, NormalizedConfig, Vendor
from app.remediation.engine import apply_remediation

REPO = Path(__file__).resolve().parents[2]

LOGGING_LINE = "audit-stream destination 10.44.60.20"


def _config(vendor: Vendor, lines=(LOGGING_LINE,)) -> NormalizedConfig:
    return NormalizedConfig(
        device=DeviceInfo(vendor=vendor, hostname="dev"),
        raw_config="\n".join(lines),
        raw_lines=list(lines),
    )


def _applied(field: str, value: str, line: int = 1) -> AIFieldMapping:
    return AIFieldMapping(
        line_number=line, raw_line="x", normalized_field=field, extracted_value=value,
        confidence=0.95, confidence_tier="high", reasoning="", source="learned_mapping",
        final_value=value,
    )


def _rule_ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


def test_uninterpreted_logging_line_on_unknown_vendor_gives_no_log001_fail():
    result = analyze(_config(Vendor.UNKNOWN))
    assert "LOG-001" not in _rule_ids(result)
    assert "LOG-002" not in _rule_ids(result)
    assert "BOUNDARY-002" not in _rule_ids(result)


def test_unknown_vendor_with_no_evaluated_evidence_is_not_assessed():
    result = analyze(_config(Vendor.UNKNOWN))
    assert result.findings == []
    assert result.score is None
    assert result.devices[0]["assessed"] is False


def test_confirmed_vendor_absence_still_fails():
    result = analyze(_config(Vendor.CISCO_IOS, ["hostname R1"]))
    assert {"LOG-001", "LOG-002"} <= _rule_ids(result)
    assert result.score is not None and result.devices[0]["assessed"] is True


def test_unknown_vendor_applied_value_is_evaluated_and_scored():
    cfg = _config(Vendor.UNKNOWN)
    cfg.logging.remote_hosts.append("10.44.60.20")
    cfg.ai_mappings.append(_applied("logging.remote_hosts", "10.44.60.20"))
    result = analyze(cfg)
    assert "LOG-001" not in _rule_ids(result)
    assert result.score == 100 and result.devices[0]["assessed"] is True


def test_ntp_auth_fails_on_unknown_vendor_only_when_explicitly_disabled():
    cfg = _config(Vendor.UNKNOWN)
    cfg.ntp.servers.append("10.44.70.10")
    cfg.ai_mappings.append(_applied("ntp.servers", "10.44.70.10"))
    assert "LOG-002" not in _rule_ids(analyze(cfg))

    cfg.ai_mappings.append(_applied("ntp.authentication_enabled", "false", line=2))
    assert "LOG-002" in _rule_ids(analyze(cfg))


def test_multi_config_score_ignores_only_unassessed_devices():
    unknown = _config(Vendor.UNKNOWN)
    cisco = _config(Vendor.CISCO_IOS, ["hostname R1"])
    mixed = analyze_multiple([unknown, cisco])
    assert mixed.score == analyze(cisco).score
    assert [d["assessed"] for d in mixed.devices] == [False, True]
    assert analyze_multiple([unknown, _config(Vendor.UNKNOWN)]).score is None


def test_ntp_authentication_without_a_server_is_not_evaluated():
    """Only an applied value that a rule actually evaluated makes a config assessed."""
    cfg = _config(Vendor.UNKNOWN)
    cfg.ntp.authentication_enabled = True
    cfg.ai_mappings.append(_applied("ntp.authentication_enabled", "true"))
    result = analyze(cfg)
    assert result.findings == []
    assert result.score is None and result.devices[0]["assessed"] is False


def _unknown_scan_with_result(client: TestClient) -> dict:
    MappingRepository().save_mapping(LearnedMapping(
        concept="remote_syslog", normalized_field="logging.remote_hosts",
        command_pattern="audit-stream destination {value}", extraction_method="template_capture",
        confirmed=True,
    ))
    text = (REPO / "sample" / "unknown.cfg").read_bytes()
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        scan = client.post("/api/scan", files=[("files", ("unknown.cfg", text, "text/plain"))]).json()
    assert scan["devices"][0]["vendor"] == "unknown"
    assert scan["score"] is not None  # a stored compliance result exists
    return scan


def test_remediation_routes_never_reparse_an_unconfirmed_config_as_cisco():
    client = TestClient(app)
    scan = _unknown_scan_with_result(client)

    # Phase 8: the command-text /verify route is gone — nothing a client sends becomes configuration
    verify = client.post("/api/verify", json={"scan_id": scan["scan_id"], "remediation_commands": ""})
    assert verify.status_code in (404, 405)
    download = client.post("/api/download-fixed", json={"scan_id": scan["scan_id"]})
    assert download.status_code == 409

    result = get_scan_store()[scan["scan_id"]]["result"]
    result.findings.append(Finding(rule_id="LOG-002", title="t", severity=Severity.MEDIUM, description="d",
                                   device_hostname="unknown", vendor="unknown"))
    remediate = client.post("/api/remediate", json={
        "scan_id": scan["scan_id"], "rule_id": "LOG-002", "device_hostname": "unknown",
    })
    # Phase 8 reports the block as a status the UI shows ("unverified vendor") instead of a 409
    assert remediate.status_code == 200
    body = remediate.json()
    assert body["status"] == "vendor_unverified" and body["fixed_config"] is None and body["diff"] == ""


def test_apply_remediation_refuses_an_unknown_vendor():
    with pytest.raises(ValueError):
        apply_remediation(_config(Vendor.UNKNOWN), "")


@pytest.mark.parametrize("ai_available", [False, True])
def test_unknown_cfg_without_usable_interpretations_is_not_assessed(ai_available):
    """With AI on but nothing interpreted this used to score 100/100."""
    interpreter = MagicMock(return_value=[])
    text = (REPO / "sample" / "unknown.cfg").read_bytes()
    with patch("app.api.routes.scan.interpret_lines", interpreter), \
         patch("app.api.routes.scan.is_available", return_value=ai_available):
        resp = TestClient(app).post("/api/scan", files=[("files", ("unknown.cfg", text, "text/plain"))])
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["score"] is None
    # only suspected lexicon-heuristic findings (Phase 5), never scored
    assert data["posture"] is None
    assert data["findings"] and all(f["assurance"] == "heuristic" for f in data["findings"])
    adaptive = data["adaptive"]
    assert adaptive["assessed"] is False
    assert adaptive["score_provisional"] is True
    assert any("not assessed" in r for r in adaptive["provisional_reasons"])
    # LOG-001 is now a probable PASS from lexicon heuristics (Phase 5); SNMP stays not configured
    assert any("MGMT-004" in r and "not found" in r for r in adaptive["provisional_reasons"])
