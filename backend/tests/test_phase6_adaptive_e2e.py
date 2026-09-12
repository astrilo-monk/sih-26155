"""
Phase 6 — End-to-end adaptive learning acceptance test.

Demonstrates:

    Unknown syntax → AI interpretation → admin confirmation →
    mapping persisted → same syntax recognized automatically later.

The system does not retrain the AI model. It learns by persisting
administrator-confirmed syntax-to-concept mappings in SQLite.

All AI calls are mocked.
"""

import dataclasses
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.adaptive.capture import capture_unrecognized_lines
from app.ai.interpretation_schemas import ConfidenceLevel, InterpretationResult, InterpretationStatus
from app.analysis.engine import analyze
from app.api.routes.scan import get_scan_store
from app.db.mappings import LearnedMapping, MappingRepository
from app.main import app
from app.models.normalized import Vendor
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.detector import detect_vendor
from app.parsers.fortinet import FortinetParser


FIXTURES = Path(__file__).parent / "fixtures"

FIRST_CONFIG = """\
system-name EDGE-GW-01
uplink mtu 1500
secure-shell protocol-version 1
remote-console protocol telnet
audit-stream destination 10.44.60.20
"""

SECOND_CONFIG = """\
system-name EDGE-GW-02
uplink mtu 9000
secure-shell protocol-version 2
remote-console protocol telnet
audit-stream destination 10.9.9.9
"""

AI_SUGGESTIONS = {
    "system-name": ("device.hostname", "EDGE-GW-01", "device_hostname"),
    "secure-shell": ("management.ssh_version", "1", "ssh_protocol_version"),
    "remote-console": ("management.telnet_enabled", "true", "telnet_management_access"),
    "audit-stream": ("logging.remote_hosts", "10.44.60.20", "remote_syslog_destination"),
}


def _mock_ai(lines):
    """MEDIUM-confidence suggestions: meaningful, but must be confirmed by an admin."""
    results = []
    for ln in lines:
        field, value, concept = AI_SUGGESTIONS[ln.raw_line.split()[0]]
        results.append(InterpretationResult(
            line_number=ln.line_number,
            raw_line=ln.raw_line,
            likely_vendor="generic",
            security_concept=concept,
            normalized_field=field,
            extracted_value=value,
            confidence=ConfidenceLevel.MEDIUM,
            numeric_confidence=0.78,
            reasoning=f"'{ln.raw_line.strip()}' expresses {concept}",
            status=InterpretationStatus.INTERPRETED,
        ))
    return results


def _scan(client, text, interpreter):
    with patch("app.api.routes.scan.interpret_lines", interpreter), \
         patch("app.api.routes.scan.is_available", return_value=True):
        resp = client.post("/api/scan", files=[("files", ("edge.cfg", text.encode(), "text/plain"))])
    assert resp.status_code == 200, resp.text
    return resp.json()


def _rule_ids(scan):
    return {f["rule_id"] for f in scan["findings"]}


def test_adaptive_learning_first_scan_then_second_scan_without_ai():
    client = TestClient(app)
    print("\n=== ADAPTIVE LEARNING DEMO ===")

    # ── FIRST SCAN ───────────────────────────────────────────────────────────
    assert detect_vendor(FIRST_CONFIG) == Vendor.UNKNOWN
    assert MappingRepository().list_mappings() == []                          # 4. no learned mapping

    ai = MagicMock(side_effect=_mock_ai)
    first = _scan(client, FIRST_CONFIG, ai)
    adaptive = first["adaptive"]

    captured = [ln["raw_line"] for ln in adaptive["unrecognized_lines"]]
    assert "secure-shell protocol-version 1" in captured                     # 1. unknown syntax detected
    assert "remote-console protocol telnet" in captured                      # 2. relevance filter keeps it
    assert "uplink mtu 1500" not in captured                                 #    …and drops noise
    print(f"[scan 1] unknown syntax captured: {captured}")

    assert ai.call_count == 1                                                # 5. one batched AI request
    assert len(ai.call_args.args[0]) == 4
    assert adaptive["ai_called"] is True
    assert {i["normalized_field"] for i in adaptive["interpretations"]} == {  # 6. interpretation produced
        "device.hostname", "management.ssh_version",
        "management.telnet_enabled", "logging.remote_hosts",
    }
    print(f"[scan 1] AI interpreted {len(adaptive['interpretations'])} lines in 1 request")

    # MEDIUM confidence: nothing applied yet, rule still fails, score provisional
    assert "LOG-001" in _rule_ids(first)
    assert adaptive["score_provisional"] is True
    assert adaptive["pending_review"] == 4

    scan_id = first["scan_id"]
    queue = client.get(f"/api/adaptive/scans/{scan_id}/review").json()
    for item in queue["items"]:                                              # 7. admin confirmation
        resp = client.post(f"/api/adaptive/scans/{scan_id}/review/{item['item_id']}/accept")
        assert resp.status_code == 200, resp.text
        print(f"[admin] confirmed line {item['line_number']}: {item['raw_line'].strip()} "
              f"→ {item['normalized_field']} = {item['extracted_value']}")
    final_first = resp.json()["scan"]

    mappings = MappingRepository().list_mappings()                            # 8. mapping persisted
    assert {m.command_pattern for m in mappings} == {
        "system-name {value}",
        "secure-shell protocol-version {value}",
        "remote-console protocol telnet",
        "audit-stream destination {value}",
    }
    assert all(m.confirmed for m in mappings)
    print(f"[db] persisted {len(mappings)} learned mappings")

    cfg1 = get_scan_store()[scan_id]["configs"][0]                           # 9. normalizes correctly
    assert cfg1.device.hostname == "EDGE-GW-01"
    assert cfg1.management.ssh_version == 1
    assert cfg1.management.telnet_enabled is True
    assert cfg1.logging.remote_hosts == ["10.44.60.20"]

    assert "LOG-001" not in _rule_ids(final_first)                           # 10. rule evaluates value
    assert "LOG-002" in _rule_ids(final_first)
    assert final_first["devices"][0]["hostname"] == "EDGE-GW-01"
    assert final_first["adaptive"]["pending_review"] == 0

    # ── SECOND SCAN ──────────────────────────────────────────────────────────
    ai_second = MagicMock(side_effect=_mock_ai)
    second = _scan(client, SECOND_CONFIG, ai_second)
    adaptive2 = second["adaptive"]

    assert len(adaptive2["unrecognized_lines"]) == 4                         # 1. unknown lines detected
    sources = {m["raw_line"]: m for m in adaptive2["ai_mappings"]}
    assert all(m["source"] == "learned_mapping" for m in sources.values())    # 2. learned mappings match
    assert sources["secure-shell protocol-version 2"]["final_value"] == "2"  # 3. value extracted
    assert sources["audit-stream destination 10.9.9.9"]["final_value"] == "10.9.9.9"
    assert adaptive2["learned_matches"] == 4

    cfg2 = get_scan_store()[second["scan_id"]]["configs"][0]                  # 4. NormalizedConfig populated
    assert cfg2.device.hostname == "EDGE-GW-02"
    assert cfg2.management.ssh_version == 2
    assert cfg2.management.telnet_enabled is True
    assert cfg2.logging.remote_hosts == ["10.9.9.9"]

    assert second["score"] is not None                                       # 5. rule evaluates it
    assert "LOG-001" not in _rule_ids(second)
    assert second["score"] == final_first["score"]

    assert ai_second.call_count == 0                                         # 6. AI NOT called
    assert adaptive2["ai_called"] is False
    assert adaptive2["pending_review"] == 0
    print(f"[scan 2] {adaptive2['learned_matches']} lines recognized from learned mappings — "
          f"AI calls: {ai_second.call_count}; score={second['score']}")

    # The deterministic rule stays the authority: without the syslog line it fails again
    third = _scan(client, "secure-shell protocol-version 2\n", MagicMock(side_effect=_mock_ai))
    assert "LOG-001" in _rule_ids(third)
    assert third["adaptive"]["ai_called"] is False
    print("=== Unknown syntax → AI interpretation → admin confirmation → "
          "mapping persisted → same syntax recognized automatically later ===")


def test_high_confidence_and_learned_values_never_mask_each_other():
    """AI must not override a value that a confirmed learned mapping already set."""
    MappingRepository().save_mapping(LearnedMapping(
        concept="ssh_protocol_version",
        normalized_field="management.ssh_version",
        command_pattern="secure-shell protocol-version {value}",
        extraction_method="template_capture",
        confirmed=True,
    ))
    text = "secure-shell protocol-version 1\nsecure-shell fallback-version 2\n"

    def high_ai(lines):
        return [InterpretationResult(
            line_number=ln.line_number, raw_line=ln.raw_line, likely_vendor="generic",
            security_concept="ssh_protocol_version", normalized_field="management.ssh_version",
            extracted_value="2", confidence=ConfidenceLevel.HIGH, numeric_confidence=0.95,
            reasoning="looks like SSH version", status=InterpretationStatus.INTERPRETED,
        ) for ln in lines]

    scan = _scan(TestClient(app), text, MagicMock(side_effect=high_ai))
    records = {m["line_number"]: m for m in scan["adaptive"]["ai_mappings"]}

    assert records[1]["source"] == "learned_mapping"
    assert records[2]["source"] == "needs_review"
    assert get_scan_store()[scan["scan_id"]]["configs"][0].management.ssh_version == 1


# ── REGRESSION: Cisco / FortiGate behavior unchanged ─────────────────────────

@pytest.mark.parametrize("fixture,parser", [
    ("cisco_vulnerable.cfg", CiscoIOSParser),
    ("cisco_secure.cfg", CiscoIOSParser),
    ("fortinet_vulnerable.cfg", FortinetParser),
    ("fortinet_secure.cfg", FortinetParser),
])
@pytest.mark.parametrize("with_unrelated_mapping", [False, True])
def test_known_vendor_fixtures_unchanged(fixture, parser, with_unrelated_mapping):
    if with_unrelated_mapping:
        MappingRepository().save_mapping(LearnedMapping(
            concept="remote_syslog_destination",
            normalized_field="logging.remote_hosts",
            command_pattern="audit-stream destination {value}",
            extraction_method="template_capture",
            confirmed=True,
        ))

    text = (FIXTURES / fixture).read_text()
    expected_config = parser().parse(text)
    capture_unrecognized_lines(expected_config)
    expected = analyze(expected_config)

    interpreter = MagicMock()
    with patch("app.api.routes.scan.interpret_lines", interpreter):
        resp = TestClient(app).post("/api/scan", files=[("files", (fixture, text.encode(), "text/plain"))])
    assert resp.status_code == 200
    data = resp.json()

    assert interpreter.call_count == 0
    assert data["adaptive"] is None
    assert data["score"] == expected.score
    assert sorted((f["rule_id"], f["severity"], tuple(f["line_numbers"])) for f in data["findings"]) == \
        sorted((f.rule_id, f.severity.value, tuple(f.line_numbers)) for f in expected.findings)

    stored = get_scan_store()[data["scan_id"]]["configs"][0]
    assert dataclasses.asdict(stored) == dataclasses.asdict(expected_config)
