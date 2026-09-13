"""
Integration tests for unknown-vendor adaptive pipeline.

Tests the full flow: unknown vendor -> Phase 1 capture -> Phase 2 Groq
interpretation -> display-only API response.

ALL Groq requests are mocked. No real Groq API calls are made.

Tests:
A - Unknown vendor reaches adaptive pipeline (no 422 rejection)
B - Unknown vendor never invokes the legacy interpreter (Phase 7: the AI judge is its only AI path)
D - Groq unavailable (graceful degradation)
E - Phase 3 AdaptiveMapper safely mediates AI → config (HIGH auto-mapped)
E2 - MEDIUM confidence NOT written to config
F - Existing Cisco/Fortinet behavior unchanged
G - Existing remediation/scoring unchanged
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.main import app
from app.parsers.detector import detect_vendor
from app.models.normalized import Vendor
from app.adaptive.capture import capture_unrecognized_lines
from app.adaptive.interpreter import interpret_lines
from app.ai.interpretation_schemas import (
    InterpretationResult,
    ConfidenceLevel,
    InterpretationStatus,
)
from app.models.normalized import NormalizedConfig, DeviceInfo


FIXTURES = Path(__file__).parent / "fixtures"

# Sample unknown-vendor config (familiar security syntax, not Cisco/Fortinet)
UNKNOWN_CONFIG = """\
system-name CORE-GATE-07

interface uplink0
 description "Internet transit"
 address 198.51.100.10/30

secure-shell protocol-version 2
secure-shell cipher-suite modern
secure-shell hostkey-size minimum 3072

operator failed-auth threshold 5
operator failed-auth quarantine 180

remote-console protocol telnet

credential-policy minimum-size 15
credential-policy complexity enforced

control-plane defense enabled
control-plane rate-guard 1200
"""


def _mock_valid_interpretations(lines):
    """Build valid InterpretationResult list for testing."""
    results = []
    for ln in lines:
        results.append(InterpretationResult(
            line_number=ln.line_number,
            raw_line=ln.raw_line,
            likely_vendor="generic",
            security_concept="ssh_host_key_minimum",
            normalized_field="management.ssh_version",
            extracted_value="3072",
            confidence=ConfidenceLevel.HIGH,
            reasoning="SSH host key minimum bit length",
            status=InterpretationStatus.INTERPRETED,
        ))
    return results


def _get_unrecognized_lines(config_text):
    """Helper: run Phase 1 capture on raw config and return UnrecognizedLines."""
    raw_lines = config_text.splitlines()
    normalized = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="unknown"),
        raw_config=config_text,
        raw_lines=raw_lines,
    )
    capture_unrecognized_lines(normalized)
    return normalized.unrecognized_lines


# ===========================================================================
# Test A - Unknown vendor reaches adaptive pipeline
# ===========================================================================

def test_a_unknown_vendor_reaches_adaptive_pipeline():
    """Unknown vendor config does NOT get 422; it reaches the adaptive pipeline."""

    vendor = detect_vendor(UNKNOWN_CONFIG)
    assert vendor == Vendor.UNKNOWN

    client = TestClient(app)

    with patch("app.api.routes.scan.is_available", return_value=False):
        with patch("app.adaptive.interpreter.is_available", return_value=False):
            response = client.post(
                "/api/scan",
                files=[("files", ("unknown.cfg", UNKNOWN_CONFIG.encode("utf-8"), "text/plain"))],
            )

    # Must NOT be 422 vendor-rejection
    assert response.status_code == 200, (
        f"Expected 200 for unknown vendor, got {response.status_code}: {response.text}"
    )

    data = response.json()
    # Vendor should be UNKNOWN
    device = data["devices"][0]
    assert device["vendor"] == "unknown"

    # Should have adaptive info
    assert data["adaptive"] is not None
    assert len(data["adaptive"]["unrecognized_lines"]) > 0
    assert "interpretations" in data["adaptive"]

    print("\nPASS [A]: Unknown vendor reaches adaptive pipeline")


# ===========================================================================
# Test B - Unknown vendor never invokes the legacy interpreter
# ===========================================================================

def test_b_unknown_vendor_never_invokes_the_legacy_interpreter(monkeypatch):
    """Unknown vendors reach AI only through the Phase 7 judge, even with the known-vendor legacy flag on."""
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "adaptive_ai_for_known_vendors", True)
    mock_interpret = MagicMock(return_value=[])

    with patch("app.api.routes.scan.interpret_lines", mock_interpret):
        with patch("app.api.routes.scan.is_available", return_value=True):
            response = TestClient(app).post(
                "/api/scan",
                files=[("files", ("unknown.cfg", UNKNOWN_CONFIG.encode("utf-8"), "text/plain"))],
            )

    assert response.status_code == 200
    data = response.json()
    assert mock_interpret.call_count == 0
    assert data["adaptive"]["interpretations"] == [] and data["adaptive"]["ai_available"] is True


# ===========================================================================
# Test D - Groq unavailable (graceful degradation)
# ===========================================================================

def test_d_groq_unavailable_graceful():
    """When Groq is unavailable, scan degrades gracefully without crashing."""

    client = TestClient(app)

    with patch("app.api.routes.scan.is_available", return_value=False):
        with patch("app.adaptive.interpreter.is_available", return_value=False):
            response = client.post(
                "/api/scan",
                files=[("files", ("unknown.cfg", UNKNOWN_CONFIG.encode("utf-8"), "text/plain"))],
            )

    assert response.status_code == 200
    data = response.json()

    # AI marked unavailable
    assert data["adaptive"] is not None
    assert data["adaptive"]["ai_available"] is False

    # Lines still preserved
    assert len(data["adaptive"]["unrecognized_lines"]) > 0

    # No misleading score
    assert data.get("score") is None
    assert len(data["findings"]) == 0

    print("\nPASS [D]: Groq unavailable handled gracefully")


def test_d2_groq_exception_graceful():
    """When Groq raises an exception, scan degrades gracefully.

    The scan route calls interpret_lines which has internal exception handling.
    We verify the scan still succeeds even if interpret_lines fails.
    """

    client = TestClient(app)

    # Mock interpret_lines to simulate the behavior when Groq fails internally
    # (interpret_lines catches exceptions and returns ai_unavailable results)
    unrecognized = _get_unrecognized_lines(UNKNOWN_CONFIG)

    def mock_failing_interpret(lines):
        """Simulate interpret_lines behavior when Groq fails."""
        from app.adaptive.interpreter import _make_unavailable_result
        return [_make_unavailable_result(ln) for ln in lines]

    with patch("app.api.routes.scan.interpret_lines", side_effect=mock_failing_interpret):
        with patch("app.api.routes.scan.is_available", return_value=True):
            with patch("app.adaptive.interpreter.is_available", return_value=True):
                response = client.post(
                    "/api/scan",
                    files=[("files", ("unknown.cfg", UNKNOWN_CONFIG.encode("utf-8"), "text/plain"))],
                )

    assert response.status_code == 200
    data = response.json()
    assert data["adaptive"] is not None

    print("\nPASS [D2]: Groq exception handled gracefully")


# ===========================================================================
# Test E - AI interpretations go through safe Phase 3 mediation
# ===========================================================================

def test_e_ai_interpretations_through_adaptive_mapper():
    """Phase 3 AdaptiveMapper is the sole intermediary between AI output and
    NormalizedConfig.  High-valid interpretations enrich config; MEDIUM/LOW
    do NOT.  The AI client never mutates NormalizedConfig directly."""

    raw_lines = UNKNOWN_CONFIG.splitlines()
    normalized = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="unknown"),
        raw_config=UNKNOWN_CONFIG,
        raw_lines=raw_lines,
    )
    capture_unrecognized_lines(normalized)

    # Phase 2 — AI produces interpretations (HIGH confidence)
    mock_interpretations = _mock_valid_interpretations(normalized.unrecognized_lines)

    # Verify the interpretations exist but Phase 2 did NOT write them
    assert len(normalized.unrecognized_lines) > 0
    assert len(mock_interpretations) > 0
    assert normalized.management.ssh_version is None  # not written yet

    # Phase 3 — AdaptiveMapper safely applies HIGH-valid interpretations
    from app.adaptive.mapper import map_interpretations
    ai_mappings = map_interpretations(normalized, mock_interpretations)

    # High-confidence mapping wrote to config via the mapper, NOT via AI
    assert normalized.management.ssh_version == 3072
    # Auto-mapped line numbers should be tracked in source_lines
    auto_mapped = [m for m in ai_mappings if m.source == "ai_auto_mapped"]
    assert len(auto_mapped) > 0
    for m in auto_mapped:
        assert m.line_number in normalized.management.source_lines

    # The compliance engine can evaluate the auto-mapped value
    # (vendor is UNKNOWN, so rules check vendor-specific conditions)
    from app.analysis.engine import analyze
    result = analyze(normalized)
    # No crash. The applied SSH value feeds only vendor-specific rules, so on an
    # unidentified vendor nothing was evaluated: not assessed rather than scored
    assert result.score is None
    assert result.devices[0]["assessed"] is False

    print("\nPASS [E]: Phase 3 AdaptiveMapper mediates AI → config safely")


def test_e2_medium_confidence_not_written_to_config():
    """MEDIUM confidence interpretations must NOT modify NormalizedConfig."""

    raw_lines = UNKNOWN_CONFIG.splitlines()
    normalized = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="unknown"),
        raw_config=UNKNOWN_CONFIG,
        raw_lines=raw_lines,
    )
    capture_unrecognized_lines(normalized)

    # Create MEDIUM-confidence interpretations
    lines = []
    for ln in normalized.unrecognized_lines:
        lines.append(InterpretationResult(
            line_number=ln.line_number,
            raw_line=ln.raw_line,
            likely_vendor="generic",
            security_concept="ssh_host_key_minimum",
            normalized_field="management.ssh_version",
            extracted_value="2",
            confidence=ConfidenceLevel.MEDIUM,
            numeric_confidence=0.60,
            reasoning="Ambiguous context",
            status=InterpretationStatus.INTERPRETED,
        ))

    from app.adaptive.mapper import map_interpretations
    ai_mappings = map_interpretations(normalized, lines)

    # Config NOT modified — safety rule
    assert normalized.management.ssh_version is None
    # Routed to needs_review
    review = [m for m in ai_mappings if m.source == "needs_review"]
    assert len(review) > 0

    print("\nPASS [E2]: MEDIUM confidence does NOT mutate config")


# ===========================================================================
# Test F - Existing Cisco/Fortinet behavior unchanged
# ===========================================================================

def test_f_cisco_behavior_unchanged():
    """Cisco config still produces deterministic findings and score."""

    cisco_config = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    assert detect_vendor(cisco_config) == Vendor.CISCO_IOS

    client = TestClient(app)
    response = client.post(
        "/api/scan",
        files=[("files", ("cisco_vulnerable.cfg", cisco_config.encode("utf-8"), "text/plain"))],
    )

    assert response.status_code == 200
    data = response.json()

    # Cisco should produce a score (not None)
    assert data["score"] is not None
    assert data["score"] < 80  # Vulnerable config should have low score
    assert len(data["findings"]) >= 5
    assert data["adaptive"] is None  # No adaptive info for known vendors

    print(f"\nPASS [F]: Cisco pipeline unchanged (score={data['score']})")


def test_f2_fortinet_behavior_unchanged():
    """FortiGate config still produces deterministic findings and score."""

    fortigate_config = (FIXTURES / "fortinet_vulnerable.cfg").read_text()
    assert detect_vendor(fortigate_config) == Vendor.FORTINET

    client = TestClient(app)
    response = client.post(
        "/api/scan",
        files=[("files", ("fortigate_vulnerable.cfg", fortigate_config.encode("utf-8"), "text/plain"))],
    )

    assert response.status_code == 200
    data = response.json()

    assert data["score"] is not None
    assert data["score"] < 80
    assert len(data["findings"]) >= 3
    assert data["adaptive"] is None

    print(f"\nPASS [F2]: FortiGate pipeline unchanged (score={data['score']})")


# ===========================================================================
# Test G - Existing remediation/scoring unchanged
# ===========================================================================

def test_g_scoring_unchanged():
    """Scoring math is unchanged."""

    from app.models.findings import Finding, Severity
    from app.analysis.scoring import calculate_score

    findings = [
        Finding(rule_id="TEST", title="test", severity=Severity.CRITICAL, description="test"),
        Finding(rule_id="TEST", title="test", severity=Severity.HIGH, description="test"),
        Finding(rule_id="TEST", title="test", severity=Severity.MEDIUM, description="test"),
        Finding(rule_id="TEST", title="test", severity=Severity.LOW, description="test"),
    ]
    # 12 + 6 + 3 + 1 = 22, so score = 78
    assert calculate_score(findings) == 78

    print("\nPASS [G1]: Scoring math unchanged")


def test_g2_remediation_compatibility_shims_never_apply_caller_commands():
    """Phase 8: the pre-Phase 8 functions remain as shims over the verified engine. Command text passed in
    is ignored, and the result is no longer 100/100 — unsafe fixes (weak passwords, AAA without a strong
    local account, any-any ACL) and fixes needing operator values are left for a human."""

    from app.remediation.engine import generate_remediation, apply_remediation
    from app.parsers.cisco_ios import CiscoIOSParser
    from app.analysis.engine import analyze

    cisco_config = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    config = CiscoIOSParser().parse(cisco_config)
    original = analyze(config)

    ssh = next(f for f in original.findings if f.rule_id == "MGMT-007")
    remediation = generate_remediation(ssh, [config])
    assert remediation["status"] == "fixed" and "+ip ssh version 2" in remediation["commands"]

    modified = apply_remediation(config, "ip http server\nno service password-encryption\nsnmp-server community public RW")
    fixed_result = analyze(CiscoIOSParser().parse(modified.raw_config))

    assert not any(line.strip() in ("ip http server", "snmp-server community public RW") for line in modified.raw_lines)
    assert {f.rule_id for f in fixed_result.findings} == {
        "MGMT-003", "MGMT-005", "MGMT-008", "BOUNDARY-001", "LOG-001", "LOG-002",
    }


# ===========================================================================
# Test H2 - One known + one unknown vendor (mixed upload)
# ===========================================================================

def test_h2_mixed_known_and_unknown_vendors():
    """Mixing known and unknown vendors: known gets deterministic scan,
    unknown gets adaptive-only response."""

    cisco_config = (FIXTURES / "cisco_vulnerable.cfg").read_text()

    client = TestClient(app)

    with patch("app.api.routes.scan.interpret_lines", return_value=[]) as mock_interpret:
        with patch("app.api.routes.scan.is_available", return_value=True):
            response = client.post(
                "/api/scan",
                files=[
                    ("files", ("cisco.cfg", cisco_config.encode("utf-8"), "text/plain")),
                    ("files", ("unknown.cfg", UNKNOWN_CONFIG.encode("utf-8"), "text/plain")),
                ],
            )

    # Since one file is unknown, the entire scan goes adaptive-only
    assert response.status_code == 200
    data = response.json()

    # Unknown vendor present
    vendors = [d["vendor"] for d in data["devices"]]
    assert "unknown" in vendors

    print("\nPASS [H2]: Mixed vendors handled correctly")


# ===========================================================================
# Test - unknown config preserves raw lines and line numbers
# ===========================================================================

def test_unknown_config_preserves_raw_lines():
    """Raw configuration and exact line numbers are preserved for unknown vendors."""

    raw_lines = UNKNOWN_CONFIG.splitlines()

    normalized = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="unknown"),
        raw_config=UNKNOWN_CONFIG,
        raw_lines=raw_lines,
    )
    capture_unrecognized_lines(normalized)

    assert len(normalized.raw_lines) == len(raw_lines)

    # Each unrecognized line should have correct line number
    for ul in normalized.unrecognized_lines:
        assert ul.line_number >= 1
        assert normalized.raw_lines[ul.line_number - 1].strip() == ul.raw_line.strip()

    print("\nPASS: Unknown config preserves raw lines and line numbers")


# ---------------------------------------------------------------------------
# Run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_a_unknown_vendor_reaches_adaptive_pipeline()
    test_b_unknown_vendor_never_invokes_the_legacy_interpreter()
    test_d_groq_unavailable_graceful()
    test_d2_groq_exception_graceful()
    test_e_ai_interpretations_through_adaptive_mapper()
    test_e2_medium_confidence_not_written_to_config()
    test_f_cisco_behavior_unchanged()
    test_f2_fortinet_behavior_unchanged()
    test_g_scoring_unchanged()
    test_g2_remediation_unchanged()
    test_h2_mixed_known_and_unknown_vendors()
    test_unknown_config_preserves_raw_lines()

    print("\n")
    print("============================================")
    print("ALL UNKNOWN-VENDOR INTEGRATION TESTS PASSED")
    print("============================================")
