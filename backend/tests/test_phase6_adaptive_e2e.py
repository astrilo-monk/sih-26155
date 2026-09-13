"""
Phase 6 — adaptive learning: confirmed learned mappings and AI output never mask each other,
and known-vendor scans are unchanged by learned mappings.

The unknown-vendor demo (AI interpretation → admin confirmation → learned mapping) was retired with the
unknown-vendor legacy interpreter in Phase 7; its successor is the recognizer loop
(``test_phase6_recognizers``) and the AI judge → Training path (``test_phase7_ai_judge``).

All AI calls are mocked.
"""

import dataclasses
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.adaptive.capture import capture_unrecognized_lines
from app.adaptive.service import AdaptiveService
from app.ai.interpretation_schemas import ConfidenceLevel, InterpretationResult, InterpretationStatus
from app.analysis.engine import analyze
from app.api.routes.scan import get_scan_store
from app.db.mappings import LearnedMapping, MappingRepository
from app.main import app
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.fortinet import FortinetParser


FIXTURES = Path(__file__).parent / "fixtures"


def test_high_confidence_and_learned_values_never_mask_each_other():
    """AI must not override a value that a confirmed learned mapping already set."""
    repository = MappingRepository()
    repository.save_mapping(LearnedMapping(
        concept="ssh_protocol_version",
        normalized_field="management.ssh_version",
        command_pattern="secure-shell protocol-version {value}",
        extraction_method="template_capture",
        confirmed=True,
    ))
    text = "secure-shell protocol-version 1\nsecure-shell fallback-version 2\n"
    config = NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN), raw_config=text, raw_lines=text.splitlines())
    capture_unrecognized_lines(config)

    def high_ai(lines):
        return [InterpretationResult(
            line_number=ln.line_number, raw_line=ln.raw_line, likely_vendor="generic",
            security_concept="ssh_protocol_version", normalized_field="management.ssh_version",
            extracted_value="2", confidence=ConfidenceLevel.HIGH, numeric_confidence=0.95,
            reasoning="looks like SSH version", status=InterpretationStatus.INTERPRETED,
        ) for ln in lines]

    service = AdaptiveService(repository=repository, interpreter=MagicMock(side_effect=high_ai),
                              ai_available=lambda: True)
    records = {r.line_number: r for r in service.process(config).records}

    assert records[1].source == "learned_mapping"
    assert records[2].source == "needs_review"
    assert config.management.ssh_version == 1


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
