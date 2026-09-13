"""
End-to-end Phase 3 tests covering the full adaptive pipeline:

    Phase 1 capture → Phase 2 AI interpretation → Phase 3 adaptive mapping
        → compliance analysis → scoring → remediation → rescan

All Groq/AI requests are mocked. No real API calls are made.

Tests:
  1  - Full pipeline: unknown vendor → AI HIGH interpretations →
      vendor evidence (reporting only) → compliance analysis → findings + score
  2  - HIGH confidence valid interpretations are auto-mapped to config
  3  - MEDIUM confidence interpretations do NOT mutate config (needs_review)
  4  - LOW confidence interpretations do NOT mutate config (needs_training)
  5  - Container fields (interfaces[].name) are rejected even at HIGH
  6  - Vendor evidence reported from unanimous HIGH entries; device vendor unchanged
  7  - Vendor stays UNKNOWN when HIGH auto-mapped entries conflict
  8  - HIGH confidence with invalid type conversion → needs_review
  9  - AI unavailable → graceful degradation (no score, no findings)
  10 - Remediation round-trip: scan → download-fixed → re-scan → score 100
"""

import sys
import copy
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.main import app
from app.api.routes.scan import get_scan_store
from app.parsers.detector import detect_vendor
from app.models.normalized import (
    Vendor,
    NormalizedConfig,
    DeviceInfo,
    AIFieldMapping,
)
from app.adaptive.capture import capture_unrecognized_lines
from app.adaptive.mapper import (
    map_interpretations,
    determine_tier,
    ConfidenceTier,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
)
from app.ai.interpretation_schemas import (
    InterpretationResult,
    ConfidenceLevel,
    InterpretationStatus,
)
from app.analysis.engine import analyze


FIXTURES = Path(__file__).parent / "fixtures"

# ── Test config: unknown vendor, security-relevant lines ──────────────────────
# None of these lines match Cisco or Fortinet detection patterns, so
# detect_vendor returns Vendor.UNKNOWN.  Each line is security-relevant
# (contains keywords like "secure", "ssh", "auth") and will be captured
# by Phase 1 capture_unrecognized_lines.
E2E_CONFIG = (
    "secure-shell protocol-version 1\n"
    "ssh host-key minimum 2048\n"
    "operator failed-auth threshold 5\n"
)


def _get_unrecognized_lines(config_text):
    """Run Phase 1 capture on raw config and return UnrecognizedLine list."""
    raw_lines = config_text.splitlines()
    normalized = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="unknown"),
        raw_config=config_text,
        raw_lines=raw_lines,
    )
    capture_unrecognized_lines(normalized)
    return normalized, normalized.unrecognized_lines


def _build_mock_interpretations(pairs):
    """Create a mock interpret_lines callable.

    *pairs* is a list of tuples:
        (normalized_field, extracted_value, likely_vendor,
         numeric_confidence, ConfidenceLevel)

    The returned function accepts a list of UnrecognizedLine and returns
    one InterpretationResult per line (in order), matching line numbers.
    """

    def _mock(lines):
        results = []
        for i, ln in enumerate(lines):
            if i < len(pairs):
                field, value, vendor, numeric, conf = pairs[i]
            else:
                field, value, vendor = "unknown", None, "unknown"
                numeric, conf = 0.30, ConfidenceLevel.LOW
            results.append(
                InterpretationResult(
                    line_number=ln.line_number,
                    raw_line=ln.raw_line,
                    likely_vendor=vendor,
                    security_concept="test_concept",
                    normalized_field=field,
                    extracted_value=value,
                    confidence=conf,
                    numeric_confidence=numeric,
                    reasoning="E2E test interpretation",
                    status=InterpretationStatus.INTERPRETED,
                )
            )
        return results

    return _mock


# ===========================================================================
# Test 1 — Full pipeline: unknown vendor → AI → Phase 3 → vendor ID → analyze
# ===========================================================================

def test_e2e_full_pipeline_high_confidence_vendor_identified():
    """End-to-end: unknown vendor config, AI believes it is Cisco IOS (HIGH),
    Phase 3 auto-maps ssh_version=1. The AI vendor opinion is reported as
    evidence only — it does not set device.vendor or activate Cisco rules."""

    assert detect_vendor(E2E_CONFIG) == Vendor.UNKNOWN

    client = TestClient(app)

    # AI mocks three HIGH-confidence cisco_ios interpretations
    mock = _build_mock_interpretations([
        ("management.ssh_version", "1", "cisco_ios", 0.95, ConfidenceLevel.HIGH),
        ("management.ssh_enabled",  "true", "cisco_ios", 0.95, ConfidenceLevel.HIGH),
        ("authentication.aaa_enabled", "true", "cisco_ios", 0.95, ConfidenceLevel.HIGH),
    ])

    with patch("app.api.routes.scan.interpret_lines", side_effect=mock):
        with patch("app.api.routes.scan.is_available", return_value=True):
            resp = client.post(
                "/api/scan",
                files=[("files", ("unknown.cfg", E2E_CONFIG.encode(), "text/plain"))],
            )

    assert resp.status_code == 200
    data = resp.json()

    # AI vendor opinions are evidence only: device.vendor stays UNKNOWN
    assert data["devices"][0]["vendor"] == "unknown"
    evidence = data["adaptive"]["vendor_evidence"]
    assert evidence["status"] == "identified"
    assert evidence["likely_vendor"] == "cisco_ios"

    # The applied values (SSH version, AAA) feed only vendor-specific rules, so
    # nothing was evaluated: not assessed, and no FAIL from missing data
    assert data["score"] is None
    assert data["findings"] == []
    assert data["adaptive"]["assessed"] is False

    # ssh_version was auto-mapped to 1, but the Cisco-specific MGMT-007 rule
    # is not activated by an AI vendor guess
    rule_ids = [f["rule_id"] for f in data["findings"]]
    assert "MGMT-007" not in rule_ids
    assert get_scan_store()[data["scan_id"]]["configs"][0].management.ssh_version == 1

    # Adaptive info present with auto-mapped entries
    assert data["adaptive"] is not None
    auto_mapped = [m for m in data["adaptive"]["ai_mappings"]
                   if m["source"] == "ai_auto_mapped"]
    assert len(auto_mapped) > 0

    print("\nPASS [1]: Full pipeline with vendor identification and compliance analysis")


# ===========================================================================
# Test 2 — HIGH confidence auto-mapped to config (unit-level)
# ===========================================================================

def test_e2e_high_confidence_auto_mapped_to_config():
    """Phase 3 writes HIGH-valid interpretations to NormalizedConfig fields
    and tracks source_lines."""

    normalized, unrecognized = _get_unrecognized_lines(E2E_CONFIG)
    assert len(unrecognized) == 3

    interpretations = [
        InterpretationResult(
            line_number=unrecognized[0].line_number,
            raw_line=unrecognized[0].raw_line,
            likely_vendor="cisco_ios",
            security_concept="ssh_version",
            normalized_field="management.ssh_version",
            extracted_value="1",
            confidence=ConfidenceLevel.HIGH,
            numeric_confidence=0.95,
            reasoning="SSH protocol version 1 detected",
            status=InterpretationStatus.INTERPRETED,
        ),
    ]

    mappings = map_interpretations(normalized, interpretations)

    # Config field was written by the mapper
    assert normalized.management.ssh_version == 1

    # Source line tracked
    assert unrecognized[0].line_number in normalized.management.source_lines

    # Audit record has correct disposition
    assert len(mappings) == 1
    assert mappings[0].source == "ai_auto_mapped"
    assert mappings[0].confidence_tier == "high"

    print("\nPASS [2]: HIGH confidence auto-mapped to config")


# ===========================================================================
# Test 3 — MEDIUM confidence NOT written to config (full pipeline via API)
# ===========================================================================

def test_e2e_medium_confidence_not_written_to_config():
    """MEDIUM confidence interpretations are routed to needs_review and
    do NOT mutate NormalizedConfig.  Through the API, this means the
    vendor stays UNKNOWN and no vendor-specific findings fire."""

    client = TestClient(app)

    # All lines interpreted as MEDIUM confidence (0.60)
    mock = _build_mock_interpretations([
        ("management.ssh_version", "1", "cisco_ios", 0.60, ConfidenceLevel.MEDIUM),
        ("management.ssh_version", "1", "cisco_ios", 0.60, ConfidenceLevel.MEDIUM),
        ("management.ssh_version", "1", "cisco_ios", 0.60, ConfidenceLevel.MEDIUM),
    ])

    with patch("app.api.routes.scan.interpret_lines", side_effect=mock):
        with patch("app.api.routes.scan.is_available", return_value=True):
            resp = client.post(
                "/api/scan",
                files=[("files", ("unknown.cfg", E2E_CONFIG.encode(), "text/plain"))],
            )

    assert resp.status_code == 200
    data = resp.json()

    # All mappings should be needs_review (MEDIUM never auto-maps)
    sources = [m["source"] for m in data["adaptive"]["ai_mappings"]]
    assert all(s == "needs_review" for s in sources)

    # Vendor is still UNKNOWN — no unanimous HIGH auto-mapped entries
    assert data["devices"][0]["vendor"] == "unknown"

    # No vendor-specific (MGMT-*) findings — MEDIUM didn't enrich config
    # so ssh_version, aaa_enabled, etc. remain at defaults
    rule_ids = [f["rule_id"] for f in data["findings"]]
    mgmt_rules = [r for r in rule_ids if r.startswith("MGMT-")]
    assert len(mgmt_rules) == 0

    print("\nPASS [3]: MEDIUM confidence not written to config")


# ===========================================================================
# Test 4 — LOW confidence NOT written to config (unit-level)
# ===========================================================================

def test_e2e_low_confidence_not_written_to_config():
    """LOW confidence interpretations are routed to needs_training and never
    mutate config fields."""

    normalized, unrecognized = _get_unrecognized_lines(E2E_CONFIG)

    interpretations = [
        InterpretationResult(
            line_number=ln.line_number,
            raw_line=ln.raw_line,
            likely_vendor="unknown",
            security_concept="ambiguous",
            normalized_field="management.ssh_enabled",
            extracted_value="true",
            confidence=ConfidenceLevel.LOW,
            numeric_confidence=0.30,
            reasoning="Too uncertain to map confidently",
            status=InterpretationStatus.INTERPRETED,
        )
        for ln in unrecognized
    ]

    mappings = map_interpretations(normalized, interpretations)

    # Config field was NOT written
    assert normalized.management.ssh_enabled is False  # default unchanged

    # All audit records routed to needs_training
    assert len(mappings) == len(unrecognized)
    assert all(m.source == "needs_training" for m in mappings)

    print("\nPASS [4]: LOW confidence not written to config")


# ===========================================================================
# Test 5 — Container field rejected (unit-level)
# ===========================================================================

def test_e2e_container_field_rejected():
    """Container fields like 'interfaces[].name' are NOT in FIELD_REGISTRY.
    Even with HIGH confidence, the validator rejects them → needs_review."""

    normalized, unrecognized = _get_unrecognized_lines(E2E_CONFIG)

    interpretations = [
        InterpretationResult(
            line_number=unrecognized[0].line_number,
            raw_line=unrecognized[0].raw_line,
            likely_vendor="cisco_ios",
            security_concept="interface_name",
            normalized_field="interfaces[].name",
            extracted_value="GigabitEthernet0/0",
            confidence=ConfidenceLevel.HIGH,
            numeric_confidence=0.95,
            reasoning="Looks like an interface declaration",
            status=InterpretationStatus.INTERPRETED,
        ),
    ]

    mappings = map_interpretations(normalized, interpretations)

    # NOT auto-mapped — routed to needs_review
    assert mappings[0].source == "needs_review"

    # Config has no interfaces (was not enriched)
    assert len(normalized.interfaces) == 0

    print("\nPASS [5]: Container field rejected → needs_review")


# ===========================================================================
# Test 6 — Vendor identified from unanimous HIGH auto-mapped entries (API)
# ===========================================================================

def test_e2e_vendor_identified_from_unanimous_mappings():
    """When all HIGH auto-mapped entries agree on likely_vendor, the vendor is
    reported as evidence only: device.vendor stays UNKNOWN, no vendor-specific
    rule fires and nothing is scored from values those rules would read."""

    client = TestClient(app)

    mock = _build_mock_interpretations([
        ("management.ssh_version", "1", "cisco_ios", 0.90, ConfidenceLevel.HIGH),
        ("management.ssh_enabled",  "true", "cisco", 0.90, ConfidenceLevel.HIGH),
        ("authentication.aaa_enabled", "true", "ios", 0.90, ConfidenceLevel.HIGH),
    ])

    with patch("app.api.routes.scan.interpret_lines", side_effect=mock):
        with patch("app.api.routes.scan.is_available", return_value=True):
            resp = client.post(
                "/api/scan",
                files=[("files", ("unknown.cfg", E2E_CONFIG.encode(), "text/plain"))],
            )

    assert resp.status_code == 200
    data = resp.json()

    # All three vendor aliases normalize to cisco_ios → unanimous evidence,
    # reported only; the device vendor is never set from AI output
    assert data["adaptive"]["vendor_evidence"]["status"] == "identified"
    assert data["adaptive"]["vendor_evidence"]["likely_vendor"] == "cisco_ios"
    assert data["devices"][0]["vendor"] == "unknown"
    assert data["score"] is None
    assert data["findings"] == []

    print("\nPASS [6]: Vendor identified from unanimous HIGH mappings")


# ===========================================================================
# Test 7 — Vendor NOT identified when HIGH entries conflict (API)
# ===========================================================================

def test_e2e_vendor_not_identified_when_conflicting():
    """When HIGH auto-mapped entries disagree on likely_vendor, the vendor
    stays UNKNOWN."""

    client = TestClient(app)

    mock = _build_mock_interpretations([
        ("management.ssh_version", "1", "cisco_ios", 0.95, ConfidenceLevel.HIGH),
        ("management.ssh_enabled",  "true", "fortinet", 0.95, ConfidenceLevel.HIGH),
        ("authentication.aaa_enabled", "true", "cisco_ios", 0.95, ConfidenceLevel.HIGH),
    ])

    with patch("app.api.routes.scan.interpret_lines", side_effect=mock):
        with patch("app.api.routes.scan.is_available", return_value=True):
            resp = client.post(
                "/api/scan",
                files=[("files", ("unknown.cfg", E2E_CONFIG.encode(), "text/plain"))],
            )

    assert resp.status_code == 200
    data = resp.json()

    # CISCO_IOS and FORTINET disagree → vendor stays UNKNOWN
    assert data["devices"][0]["vendor"] == "unknown"
    assert data["adaptive"]["vendor_evidence"]["status"] == "conflicting"

    # Config WAS enriched (auto-mapped entries exist) but no vendor-specific rules fire
    auto_mapped = [m for m in data["adaptive"]["ai_mappings"]
                   if m["source"] == "ai_auto_mapped"]
    assert len(auto_mapped) > 0

    # UNKNOWN vendor → no vendor-specific (MGMT-*) findings fire
    # (absence-based LOG-001/LOG-002 do not fail on an unknown vendor either — Phase 1c)
    rule_ids = [f["rule_id"] for f in data["findings"]]
    mgmt_rules = [r for r in rule_ids if r.startswith("MGMT-")]
    assert len(mgmt_rules) == 0

    print("\nPASS [7]: Vendor not identified when conflicting mappings")


# ===========================================================================
# Test 8 — HIGH confidence + invalid type conversion → needs_review (unit)
# ===========================================================================

def test_e2e_invalid_type_conversion_routed_to_review():
    """HIGH confidence interpretation whose extracted value cannot be
    converted to the field's expected type is routed to needs_review,
    NOT auto-mapped, and config is not mutated."""

    normalized, unrecognized = _get_unrecognized_lines(E2E_CONFIG)

    interpretations = [
        InterpretationResult(
            line_number=unrecognized[0].line_number,
            raw_line=unrecognized[0].raw_line,
            likely_vendor="cisco_ios",
            security_concept="ssh_version",
            normalized_field="management.ssh_version",  # expects int
            extracted_value="not_a_number",              # cannot convert to int
            confidence=ConfidenceLevel.HIGH,
            numeric_confidence=0.95,
            reasoning="Confident but value is non-numeric",
            status=InterpretationStatus.INTERPRETED,
        ),
    ]

    mappings = map_interpretations(normalized, interpretations)

    # NOT auto-mapped due to validation failure
    assert mappings[0].source == "needs_review"
    assert mappings[0].confidence_tier == "high"

    # Config field remains at default
    assert normalized.management.ssh_version is None

    print("\nPASS [8]: HIGH confidence + invalid type → needs_review")


# ===========================================================================
# Test 9 — AI unavailable → graceful degradation (API)
# ===========================================================================

def test_e2e_ai_unavailable_graceful():
    """When AI is unavailable, the scan degrades gracefully: no score,
    no findings, adaptive-only display response."""

    client = TestClient(app)

    with patch("app.api.routes.scan.is_available", return_value=False):
        with patch("app.adaptive.interpreter.is_available", return_value=False):
            resp = client.post(
                "/api/scan",
                files=[("files", ("unknown.cfg", E2E_CONFIG.encode(), "text/plain"))],
            )

    assert resp.status_code == 200
    data = resp.json()

    # AI marked unavailable
    assert data["adaptive"]["ai_available"] is False

    # No compliance analysis — no score, no findings
    assert data.get("score") is None
    assert data.get("total_findings") is None
    assert len(data["findings"]) == 0

    # Adaptive info still returned (display-only)
    assert len(data["adaptive"]["unrecognized_lines"]) > 0

    print("\nPASS [9]: AI unavailable handled gracefully")


# ===========================================================================
# Test 10 — Remediation round-trip (full HTTP API flow)
# ===========================================================================

def test_e2e_remediation_round_trip():
    """Full remediation round-trip through the HTTP API:
    scan vulnerable Cisco config → download-fixed → re-scan → score 100."""

    cisco_config = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    assert detect_vendor(cisco_config) == Vendor.CISCO_IOS

    client = TestClient(app)

    # Step 1 — scan the vulnerable config (known vendor, no AI)
    scan_resp = client.post(
        "/api/scan",
        files=[("files", ("cisco_vuln.cfg", cisco_config.encode(), "text/plain"))],
    )
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["score"] is not None
    assert scan_data["score"] < 80
    assert len(scan_data["findings"]) >= 5

    scan_id = scan_data["scan_id"]

    # Step 2 — download the fully remediated config
    dl_resp = client.post(
        "/api/download-fixed",
        json={"scan_id": scan_id},
    )
    assert dl_resp.status_code == 200
    remediated_text = dl_resp.text
    assert "ip ssh version 2" in remediated_text  # SSHv1 was fixed

    # Step 3 — re-scan the remediated config
    rescan_resp = client.post(
        "/api/scan",
        files=[("files", ("cisco_fixed.cfg", remediated_text.encode(), "text/plain"))],
    )
    assert rescan_resp.status_code == 200
    rescan_data = rescan_resp.json()

    # Step 4 — all findings resolved, perfect score
    assert rescan_data["score"] == 100
    assert rescan_data["total_findings"] == 0

    print(f"\nPASS [10]: Remediation round-trip complete "
          f"(original={scan_data['score']}, fixed={rescan_data['score']})")


# ---------------------------------------------------------------------------
# Run directly
# ---------------------------------------------------------------------------

# ===========================================================================
# Regression tests for unknown.cfg fixes (Groq schema + ntp.servers)
# ===========================================================================

def test_e2e_groq_schema_includes_numeric_confidence():
    """The Groq structured-output JSON schema must include numeric_confidence
    in its required array so the API accepts the schema."""

    from app.adaptive.interpreter import INTERPRETATION_RESPONSE_FORMAT

    schema = INTERPRETATION_RESPONSE_FORMAT["json_schema"]["schema"]
    items = schema["properties"]["interpretations"]["items"]

    assert "numeric_confidence" in items["required"], (
        "numeric_confidence must be in the JSON schema 'required' array"
    )
    assert "numeric_confidence" in items["properties"]

    print("\nPASS: Groq schema includes numeric_confidence in required")


def test_e2e_ntp_servers_in_field_registry():
    """ntp.servers must be registered in FIELD_REGISTRY so Phase 3 can
    auto-map it."""

    from app.adaptive.mapper import FIELD_REGISTRY

    assert "ntp.servers" in FIELD_REGISTRY, (
        "ntp.servers must be in FIELD_REGISTRY for Phase 3 to write it"
    )

    print("\nPASS: ntp.servers registered in FIELD_REGISTRY")


def test_e2e_ntp_servers_high_confidence_writes_correctly():
    """A HIGH-confidence ntp.servers interpretation is auto-mapped to
    config.ntp.servers as a list of strings."""

    normalized, unrecognized = _get_unrecognized_lines(
        "time-sync server 10.44.70.10\n"
    )

    interp = InterpretationResult(
        line_number=unrecognized[0].line_number,
        raw_line=unrecognized[0].raw_line,
        likely_vendor="generic",
        security_concept="ntp_server",
        normalized_field="ntp.servers",
        extracted_value="10.44.70.10",
        confidence=ConfidenceLevel.HIGH,
        numeric_confidence=0.90,
        reasoning="NTP server address found",
        status=InterpretationStatus.INTERPRETED,
    )

    mappings = map_interpretations(normalized, [interp])

    assert len(mappings) == 1
    assert mappings[0].source == "ai_auto_mapped"
    assert normalized.ntp.servers == ["10.44.70.10"]

    print("\nPASS: HIGH-confidence ntp.servers auto-mapped correctly")


def test_e2e_logging_remote_hosts_resolves_log001():
    """When logging.remote_hosts is populated via Phase 3 auto-mapping,
    LOG-001 (No Remote Syslog) does not fire."""

    from app.models.normalized import NormalizedConfig, DeviceInfo
    from app.adaptive.capture import capture_unrecognized_lines
    from app.adaptive.mapper import map_interpretations
    from app.analysis.engine import analyze
    from app.models.findings import Severity

    config_text = (
        "audit-stream destination 10.44.60.20\n"
    )
    normalized, unrecognized = _get_unrecognized_lines(config_text)

    interp = InterpretationResult(
        line_number=unrecognized[0].line_number,
        raw_line=unrecognized[0].raw_line,
        likely_vendor="generic",
        security_concept="syslog_destination",
        normalized_field="logging.remote_hosts",
        extracted_value="10.44.60.20",
        confidence=ConfidenceLevel.HIGH,
        numeric_confidence=0.92,
        reasoning="Remote syslog server identified",
        status=InterpretationStatus.INTERPRETED,
    )

    map_interpretations(normalized, [interp])
    assert normalized.logging.remote_hosts == ["10.44.60.20"]

    result = analyze(normalized)

    rule_ids = [f.rule_id for f in result.findings]
    assert "LOG-001" not in rule_ids, "LOG-001 should not fire when remote_hosts is set"

    print("\nPASS: logging.remote_hosts resolves LOG-001")


def test_e2e_ntp_fields_resolve_log002():
    """When ntp.servers and ntp.authentication_enabled are populated via
    Phase 3 auto-mapping, LOG-002 (NTP not configured) does not fire."""

    from app.models.normalized import NormalizedConfig, DeviceInfo
    from app.adaptive.capture import capture_unrecognized_lines
    from app.adaptive.mapper import map_interpretations
    from app.analysis.engine import analyze

    config_text = (
        "time-sync state enabled\n"
        "time-sync authenticated enabled\n"
        "time-sync server 10.44.70.10\n"
    )
    normalized, unrecognized = _get_unrecognized_lines(config_text)

    interpretations = []
    for ln in unrecognized:
        if "time-sync server" in ln.raw_line:
            field, value = "ntp.servers", "10.44.70.10"
        elif "time-sync authenticated" in ln.raw_line:
            field, value = "ntp.authentication_enabled", "true"
        elif "time-sync state" in ln.raw_line:
            field, value = "ntp.authentication_enabled", "true"
        else:
            field, value = "unknown", None
        interpretations.append(InterpretationResult(
            line_number=ln.line_number,
            raw_line=ln.raw_line,
            likely_vendor="generic",
            security_concept="ntp",
            normalized_field=field,
            extracted_value=value,
            confidence=ConfidenceLevel.HIGH,
            numeric_confidence=0.90,
            reasoning="NTP parameter identified",
            status=InterpretationStatus.INTERPRETED,
        ))

    map_interpretations(normalized, interpretations)

    assert len(normalized.ntp.servers) > 0
    assert normalized.ntp.authentication_enabled is True

    result = analyze(normalized)

    rule_ids = [f.rule_id for f in result.findings]
    assert "LOG-002" not in rule_ids, "LOG-002 should not fire when ntp.servers and auth are set"

    print("\nPASS: ntp.servers + authentication resolves LOG-002")


def test_e2e_groq_schema_strict_and_additional_properties():
    """Verify the JSON schema is structurally valid for Groq strict mode:
    - additionalProperties is False on items
    - all properties are listed in required"""

    from app.adaptive.interpreter import INTERPRETATION_RESPONSE_FORMAT

    schema = INTERPRETATION_RESPONSE_FORMAT["json_schema"]["schema"]
    items_schema = schema["properties"]["interpretations"]["items"]

    assert items_schema.get("additionalProperties") is False
    prop_names = set(items_schema["properties"].keys())
    required_names = set(items_schema["required"])
    assert prop_names == required_names, (
        f"Groq strict mode requires all properties in 'required'. "
        f"Missing: {prop_names - required_names}"
    )

    print("\nPASS: Groq schema is strict-mode valid")


if __name__ == "__main__":
    test_e2e_full_pipeline_high_confidence_vendor_identified()
    test_e2e_high_confidence_auto_mapped_to_config()
    test_e2e_medium_confidence_not_written_to_config()
    test_e2e_low_confidence_not_written_to_config()
    test_e2e_container_field_rejected()
    test_e2e_vendor_identified_from_unanimous_mappings()
    test_e2e_vendor_not_identified_when_conflicting()
    test_e2e_invalid_type_conversion_routed_to_review()
    test_e2e_ai_unavailable_graceful()
    test_e2e_remediation_round_trip()
    test_e2e_groq_schema_includes_numeric_confidence()
    test_e2e_ntp_servers_in_field_registry()
    test_e2e_ntp_servers_high_confidence_writes_correctly()
    test_e2e_logging_remote_hosts_resolves_log001()
    test_e2e_ntp_fields_resolve_log002()
    test_e2e_groq_schema_strict_and_additional_properties()

    print("\n" + "=" * 50)
    print("ALL PHASE 3 E2E TESTS PASSED")
    print("=" * 50)
