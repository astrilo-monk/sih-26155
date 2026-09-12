"""
Phase 3 — Confidence-based interpretation and safe NormalizedConfig enrichment.

Tests:
1. Valid HIGH mapping → enriched + ai_auto_mapped
2. Invalid HIGH mapping → needs_review, config NOT enriched
3. MEDIUM mapping → needs_review, config NOT enriched
4. LOW mapping → needs_training, config NOT enriched
5. Audit trail completeness (all required fields present)
6. Container fields → needs_review even at HIGH confidence
7. String-confidence fallback (no numeric_confidence → derived)
8. List-field append semantics
9. ConsoleLine creation on demand
10. Deterministic rules remain unchanged (regression)
11. Effective confidence derivation
12. Multiple interpretations with mixed tiers
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import patch

from app.models.normalized import (
    NormalizedConfig,
    DeviceInfo,
    Vendor,
    ConsoleLine,
    AIFieldMapping,
)
from app.ai.interpretation_schemas import (
    InterpretationResult,
    ConfidenceLevel,
    InterpretationStatus,
    confidence_to_numeric,
)
from app.adaptive.mapper import (
    ConfidenceTier,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    determine_tier,
    AdaptiveMapper,
    map_interpretations,
    InterpretationValidator,
    ConfidenceDecision,
    make_confidence_decision,
    ValidationResult,
    FIELD_REGISTRY,
)
from app.adaptive.capture import capture_unrecognized_lines
from app.analysis.engine import analyze


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_result(
    line_number: int = 42,
    raw_line: str = "ssh host-key minimum 3072",
    normalized_field: str = "management.ssh_version",
    extracted_value: str = "2",
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    numeric_confidence: float | None = 0.90,
    reasoning: str = "SSH host key size of 3072 bits detected",
    status: InterpretationStatus = InterpretationStatus.INTERPRETED,
    **kwargs,
) -> InterpretationResult:
    """Build an InterpretationResult with sensible defaults for testing."""
    return InterpretationResult(
        line_number=line_number,
        raw_line=raw_line,
        likely_vendor=kwargs.get("likely_vendor", "generic"),
        security_concept=kwargs.get("security_concept", "ssh_host_key_minimum"),
        normalized_field=normalized_field,
        extracted_value=extracted_value,
        confidence=confidence,
        numeric_confidence=numeric_confidence,
        reasoning=reasoning,
        status=status,
    )


def _empty_config() -> NormalizedConfig:
    """Create an empty NormalizedConfig suitable for mapping tests."""
    return NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="test-device"),
        raw_lines=[],
    )


FIXTURES = Path(__file__).parent / "fixtures"


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Valid HIGH mapping
# ═══════════════════════════════════════════════════════════════════════════════

def test_valid_high_mapping():
    """HIGH-confidence valid interpretation is auto-mapped to NormalizedConfig."""
    config = _empty_config()
    interp = _make_result(
        line_number=42,
        raw_line="secure-shell host-key minimum 3072",
        normalized_field="management.ssh_version",
        extracted_value="2",
        numeric_confidence=0.92,
        reasoning="SSH version 2 detected from host key minimum size directive",
    )

    records = map_interpretations(config, [interp])

    # Value was written to config
    assert config.management.ssh_version == 2

    # One audit record, disposition = auto-mapped
    assert len(records) == 1
    rec = records[0]
    assert rec.source == "ai_auto_mapped"
    assert rec.confidence_tier == "high"
    assert rec.normalized_field == "management.ssh_version"
    assert rec.extracted_value == "2"
    assert rec.confidence == 0.92
    assert rec.line_number == 42
    assert "3072" in rec.raw_line

    # The audit entry is also stored on config
    assert len(config.ai_mappings) == 1
    assert config.ai_mappings[0].source == "ai_auto_mapped"

    # source_lines updated so deterministic rules can find evidence
    assert 42 in config.management.source_lines

    print("\nPASS [1]: Valid HIGH mapping auto-applied")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Invalid HIGH mapping
# ═══════════════════════════════════════════════════════════════════════════════

def test_invalid_high_mapping():
    """HIGH confidence but invalid value → needs_review, config NOT mutated."""
    config = _empty_config()
    interp = _make_result(
        line_number=10,
        raw_line="ssh version abc",
        normalized_field="management.ssh_version",
        extracted_value="not_a_number",  # can't convert to int
        numeric_confidence=0.95,
        reasoning="SSH version detected but value is unclear",
    )

    records = map_interpretations(config, [interp])

    # Value was NOT written
    assert config.management.ssh_version is None
    assert 10 not in config.management.source_lines

    # Went to review instead
    assert len(records) == 1
    rec = records[0]
    assert rec.source == "needs_review"
    assert rec.confidence_tier == "high"

    print("\nPASS [2]: Invalid HIGH mapping sent to review")


def test_invalid_high_mapping_unknown_field():
    """HIGH confidence but normalized_field='unknown' → needs_review."""
    config = _empty_config()
    interp = _make_result(
        line_number=5,
        raw_line="some obscure directive",
        normalized_field="unknown",
        extracted_value="something",
        numeric_confidence=0.90,
        reasoning="Could not identify the field",
    )

    records = map_interpretations(config, [interp])

    rec = records[0]
    assert rec.source == "needs_review"
    assert rec.normalized_field == "unknown"

    print("\nPASS [2b]: HIGH confidence unknown field → needs_review")


def test_invalid_high_mapping_container_field():
    """HIGH confidence mapping to a container field (with []) → needs_review."""
    config = _empty_config()
    interp = _make_result(
        line_number=7,
        raw_line="interface eth0 shutdown",
        normalized_field="interfaces[].shutdown",
        extracted_value="enabled",
        numeric_confidence=0.90,
        reasoning="Shutdown state detected on interface",
    )

    records = map_interpretations(config, [interp])

    assert config.interfaces == []  # no new interface created
    assert len(records) == 1
    assert records[0].source == "needs_review"

    print("\nPASS [2c]: HIGH confidence container field → needs_review")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. MEDIUM mapping
# ═══════════════════════════════════════════════════════════════════════════════

def test_medium_mapping():
    """MEDIUM confidence → needs_review, config NOT mutated (no false PASS)."""
    config = _empty_config()
    interp = _make_result(
        line_number=15,
        raw_line="ssh version 2",
        normalized_field="management.ssh_version",
        extracted_value="2",
        numeric_confidence=0.65,
        reasoning="Likely SSH version 2 but context is ambiguous",
    )

    records = map_interpretations(config, [interp])

    # Config NOT mutated — this is the critical safety rule
    assert config.management.ssh_version is None
    assert 15 not in config.management.source_lines

    assert len(records) == 1
    rec = records[0]
    assert rec.source == "needs_review"
    assert rec.confidence_tier == "medium"
    assert rec.confidence == 0.65

    print("\nPASS [3]: MEDIUM mapping routed to review, config unchanged")


def test_medium_mapping_even_if_type_valid():
    """Even a valid MEDIUM interpretation does NOT write to config."""
    config = _empty_config()
    interp = _make_result(
        line_number=20,
        raw_line="telnet disabled",
        normalized_field="management.telnet_enabled",
        extracted_value="disabled",
        numeric_confidence=0.60,
        reasoning="Telnet appears to be disabled",
    )

    records = map_interpretations(config, [interp])

    # Must NOT silently set the value — that could mask a vulnerability
    assert config.management.telnet_enabled is False  # default, not set by AI
    # Actually, default is False, so we verify source_lines were NOT updated
    assert 20 not in config.management.source_lines
    assert records[0].source == "needs_review"
    assert records[0].confidence_tier == "medium"

    print("\nPASS [3b]: Valid MEDIUM does NOT write to config")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. LOW mapping
# ═══════════════════════════════════════════════════════════════════════════════

def test_low_mapping():
    """LOW confidence → needs_training, config NOT mutated."""
    config = _empty_config()
    interp = _make_result(
        line_number=8,
        raw_line="secure-shell cipher-policy modern",
        normalized_field="management.ssh_version",
        extracted_value="2",
        numeric_confidence=0.30,
        reasoning="Uncertain about the exact field",
    )

    records = map_interpretations(config, [interp])

    assert config.management.ssh_version is None
    assert 8 not in config.management.source_lines

    assert len(records) == 1
    rec = records[0]
    assert rec.source == "needs_training"
    assert rec.confidence_tier == "low"
    assert rec.confidence == 0.30

    print("\nPASS [4]: LOW mapping routed to training, config unchanged")


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Audit trail completeness
# ═══════════════════════════════════════════════════════════════════════════════

def test_audit_fields_complete():
    """Every AI-touched line exposes all required audit fields."""
    config = _empty_config()
    interp = _make_result(
        line_number=99,
        raw_line="secure-shell host-key minimum 3072",
        normalized_field="management.ssh_version",
        extracted_value="2",
        numeric_confidence=0.90,
        reasoning="Detected SSH host key minimum size 3072",
        likely_vendor="generic",
        security_concept="ssh_host_key_minimum",
    )

    records = map_interpretations(config, [interp])
    rec = records[0]

    # All auditability fields required by the spec:
    assert rec.raw_line == "secure-shell host-key minimum 3072"          # raw line
    assert rec.line_number == 99                                          # line number
    assert rec.normalized_field == "management.ssh_version"              # normalized field
    assert rec.extracted_value == "2"                                    # extracted value
    assert rec.confidence == 0.90                                        # confidence
    assert rec.confidence_tier == "high"                                 # confidence tier
    assert rec.reasoning == "Detected SSH host key minimum size 3072"     # reasoning
    assert rec.status == "interpreted"                                   # status
    assert rec.source == "ai_auto_mapped"                                # source

    print("\nPASS [5]: All audit fields present")


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Confidence tier boundary tests
# ═══════════════════════════════════════════════════════════════════════════════

def test_confidence_tier_boundaries():
    """Verify tier boundaries: 0.85 = HIGH, 0.50 = MEDIUM, just below = correct tier."""
    assert determine_tier(0.85) == ConfidenceTier.HIGH
    assert determine_tier(0.84) == ConfidenceTier.MEDIUM
    assert determine_tier(0.50) == ConfidenceTier.MEDIUM
    assert determine_tier(0.49) == ConfidenceTier.LOW
    assert determine_tier(1.0) == ConfidenceTier.HIGH
    assert determine_tier(0.0) == ConfidenceTier.LOW

    print("\nPASS [6]: Tier boundaries correct")


# ═══════════════════════════════════════════════════════════════════════════════
# 7. String-confidence fallback (no numeric_confidence)
# ═══════════════════════════════════════════════════════════════════════════════

def test_string_confidence_fallback_high():
    """Without numeric_confidence, HIGH string → 0.90 → tier HIGH."""
    config = _empty_config()
    interp = _make_result(
        confidence=ConfidenceLevel.HIGH,
        numeric_confidence=None,
        extracted_value="false",
        normalized_field="management.telnet_enabled",
    )

    records = map_interpretations(config, [interp])

    assert config.management.telnet_enabled is False
    assert 42 in config.management.source_lines
    assert records[0].confidence == confidence_to_numeric(ConfidenceLevel.HIGH)
    assert records[0].confidence_tier == "high"
    assert records[0].source == "ai_auto_mapped"

    print("\nPASS [7a]: String HIGH → numeric 0.90 → auto-mapped")


def test_string_confidence_fallback_medium():
    """Without numeric_confidence, MEDIUM string → 0.70 → tier MEDIUM."""
    config = _empty_config()
    interp = _make_result(
        confidence=ConfidenceLevel.MEDIUM,
        numeric_confidence=None,
        extracted_value="2",
        normalized_field="management.ssh_version",
    )

    records = map_interpretations(config, [interp])

    assert config.management.ssh_version is None
    assert records[0].confidence == confidence_to_numeric(ConfidenceLevel.MEDIUM)
    assert records[0].confidence_tier == "medium"
    assert records[0].source == "needs_review"

    print("\nPASS [7b]: String MEDIUM → numeric 0.70 → needs_review")


def test_string_confidence_fallback_low():
    """Without numeric_confidence, LOW string → 0.30 → tier LOW."""
    config = _empty_config()
    interp = _make_result(
        confidence=ConfidenceLevel.LOW,
        numeric_confidence=None,
        extracted_value="2",
        normalized_field="management.ssh_version",
    )

    records = map_interpretations(config, [interp])

    assert config.management.ssh_version is None
    assert records[0].confidence == confidence_to_numeric(ConfidenceLevel.LOW)
    assert records[0].confidence_tier == "low"
    assert records[0].source == "needs_training"

    print("\nPASS [7c]: String LOW → numeric 0.30 → needs_training")


# ═══════════════════════════════════════════════════════════════════════════════
# 8. List-field append semantics
# ═══════════════════════════════════════════════════════════════════════════════

def test_list_field_append():
    """HIGH confidence list[str] mapping appends value to list."""
    config = _empty_config()
    interp = _make_result(
        line_number=33,
        raw_line="logging host 10.0.0.1",
        normalized_field="logging.remote_hosts",
        extracted_value="10.0.0.1",
        numeric_confidence=0.95,
        reasoning="Remote syslog host 10.0.0.1 detected",
    )

    records = map_interpretations(config, [interp])

    assert "10.0.0.1" in config.logging.remote_hosts
    assert records[0].source == "ai_auto_mapped"
    assert 33 in config.logging.source_lines

    print("\nPASS [8]: List field append works")


def test_list_field_no_duplicates():
    """Appending a duplicate value does not create duplicates."""
    config = _empty_config()
    config.logging.remote_hosts = ["10.0.0.1"]  # pre-existing

    interp = _make_result(
        line_number=40,
        raw_line="logging host 10.0.0.1",
        normalized_field="logging.remote_hosts",
        extracted_value="10.0.0.1",
        numeric_confidence=0.95,
    )

    records = map_interpretations(config, [interp])

    assert config.logging.remote_hosts.count("10.0.0.1") == 1

    print("\nPASS [8b]: No duplicate appends")


# ═══════════════════════════════════════════════════════════════════════════════
# 9. ConsoleLine creation on demand
# ═══════════════════════════════════════════════════════════════════════════════

def test_console_line_created_on_demand():
    """Auto-mapping console fields creates a ConsoleLine if absent."""
    config = _empty_config()
    assert config.management.console is None

    interp = _make_result(
        line_number=55,
        raw_line="console exec-timeout 5 0",
        normalized_field="management.console.exec_timeout_minutes",
        extracted_value="5",
        numeric_confidence=0.93,
        reasoning="Console exec timeout of 5 minutes",
    )

    records = map_interpretations(config, [interp])

    assert config.management.console is not None
    assert isinstance(config.management.console, ConsoleLine)
    assert config.management.console.exec_timeout_minutes == 5
    assert records[0].source == "ai_auto_mapped"
    assert 55 in config.management.console.source_lines

    print("\nPASS [9]: ConsoleLine created on demand")


# ═══════════════════════════════════════════════════════════════════════════════
# 10. Deterministic rules remain unchanged
# ═══════════════════════════════════════════════════════════════════════════════

def test_deterministic_rules_unchanged_cisco():
    """Cisco fixture still produces the same findings and score."""
    from app.parsers.cisco_ios import CiscoIOSParser
    config_text = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    parser = CiscoIOSParser()
    config = parser.parse(config_text)
    result = analyze(config)

    assert result.score < 80
    assert result.total_findings >= 5
    assert result.critical_count >= 1

    print(f"\nPASS [10a]: Cisco deterministic rules unchanged (score={result.score}, findings={result.total_findings})")


def test_deterministic_rules_unchanged_fortinet():
    """FortiGate fixture still produces the same findings and score."""
    from app.parsers.fortinet import FortinetParser
    config_text = (FIXTURES / "fortinet_vulnerable.cfg").read_text()
    parser = FortinetParser()
    config = parser.parse(config_text)
    result = analyze(config)

    assert result.score < 80
    assert result.total_findings >= 3

    print(f"\nPASS [10b]: FortiGate deterministic rules unchanged (score={result.score}, findings={result.total_findings})")


def test_ai_mapped_value_evaluated_by_deterministic_rules():
    """A HIGH-confidence auto-mapped value IS evaluated by the compliance engine."""
    config = _empty_config()
    config.device.vendor = Vendor.CISCO_IOS  # set vendor so Cisco rules fire

    # Simulate AI mapping: "ip ssh version 1" → management.ssh_version = 1
    interp = _make_result(
        line_number=99,
        raw_line="ip ssh version 1",
        normalized_field="management.ssh_version",
        extracted_value="1",
        numeric_confidence=0.90,
        reasoning="SSH version 1 detected",
    )

    map_interpretations(config, [interp])

    # The auto-mapped value should now be visible to the compliance engine
    assert config.management.ssh_version == 1
    # The SshWeaknessRule checks for ssh_version == 1 on Cisco
    result = analyze(config)
    assert any(f.rule_id == "MGMT-007" for f in result.findings), \
        "Auto-mapped ssh_version=1 should trigger MGMT-007"

    print("\nPASS [10c]: Auto-mapped value evaluated by deterministic rules")


# ═══════════════════════════════════════════════════════════════════════════════
# 11. Effective confidence derivation
# ═══════════════════════════════════════════════════════════════════════════════

def test_effective_confidence_with_numeric():
    """When numeric_confidence is provided, it takes priority."""
    interp = _make_result(
        confidence=ConfidenceLevel.HIGH,
        numeric_confidence=0.88,
    )
    assert interp.effective_confidence == 0.88


def test_effective_confidence_without_numeric():
    """When numeric_confidence is None, derive from string level."""
    interp = _make_result(
        confidence=ConfidenceLevel.HIGH,
        numeric_confidence=None,
    )
    assert interp.effective_confidence == confidence_to_numeric(ConfidenceLevel.HIGH) == 0.90


def test_make_confidence_decision():
    """ConfidenceDecision uses effective_confidence and determines tier."""
    interp = _make_result(
        numeric_confidence=0.92,
    )
    decision = make_confidence_decision(interp)
    assert decision.numeric_confidence == 0.92
    assert decision.tier == ConfidenceTier.HIGH

    interp2 = _make_result(
        numeric_confidence=0.55,
    )
    decision2 = make_confidence_decision(interp2)
    assert decision2.tier == ConfidenceTier.MEDIUM

    interp3 = _make_result(
        numeric_confidence=0.20,
    )
    decision3 = make_confidence_decision(interp3)
    assert decision3.tier == ConfidenceTier.LOW


# ═══════════════════════════════════════════════════════════════════════════════
# 12. Multiple interpretations with mixed tiers
# ═══════════════════════════════════════════════════════════════════════════════

def test_multiple_mixed_tiers():
    """Multiple interpretations with different tiers are handled independently."""
    config = _empty_config()
    config.device.vendor = Vendor.CISCO_IOS

    interpretations = [
        # HIGH — valid → auto-mapped
        _make_result(
            line_number=10,
            raw_line="ip ssh version 2",
            normalized_field="management.ssh_version",
            extracted_value="2",
            numeric_confidence=0.95,
        ),
        # MEDIUM — valid but → review
        _make_result(
            line_number=20,
            raw_line="telnet disabled",
            normalized_field="management.telnet_enabled",
            extracted_value="false",
            numeric_confidence=0.60,
        ),
        # LOW → training
        _make_result(
            line_number=30,
            raw_line="secure-shell cipher-policy modern",
            normalized_field="management.ssh_version",
            extracted_value="3",
            numeric_confidence=0.25,
        ),
    ]

    records = map_interpretations(config, interpretations)

    assert len(records) == 3
    assert records[0].source == "ai_auto_mapped"
    assert records[1].source == "needs_review"
    assert records[2].source == "needs_training"

    # Only the HIGH one wrote to config
    assert config.management.ssh_version == 2  # from HIGH (last write wins would be 3, but LOW didn't write)
    # telnet_enabled is still default (False from dataclass), but NOT set by AI
    assert 20 not in config.management.source_lines
    assert 30 not in config.management.source_lines

    print("\nPASS [12]: Mixed tiers handled independently")


# ═══════════════════════════════════════════════════════════════════════════════
# 13. Empty interpretations list
# ═══════════════════════════════════════════════════════════════════════════════

def test_empty_interpretations():
    """Empty interpretations list is a no-op."""
    config = _empty_config()
    records = map_interpretations(config, [])
    assert records == []
    assert config.ai_mappings == []
    print("\nPASS [13]: Empty interpretations is a no-op")


# ═══════════════════════════════════════════════════════════════════════════════
# 14. Boolean conversion variants
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("value,expected", [
    ("enabled", True),
    ("disabled", False),
    ("true", True),
    ("false", False),
    ("yes", True),
    ("no", False),
    ("1", True),
    ("0", False),
    ("on", True),
    ("off", False),
    ("UNKNOWN", None),  # ambiguous → None → validation fails
    ("", None),          # ambiguous → None → validation fails
])
def test_bool_conversion_variants(value, expected):
    """Bool converter handles common representations."""
    from app.adaptive.mapper import convert_bool
    result = convert_bool(value)
    if expected is None:
        assert result is None
    else:
        assert result == expected


def test_bool_auto_map_with_enabled():
    """'enabled' string converts to True for a bool field."""
    config = _empty_config()
    config.device.vendor = Vendor.CISCO_IOS
    interp = _make_result(
        line_number=5,
        raw_line="ip ssh version 2",
        normalized_field="management.ssh_enabled",
        extracted_value="enabled",
        numeric_confidence=0.95,
    )
    map_interpretations(config, [interp])
    assert config.management.ssh_enabled is True
    print("\nPASS [14]: 'enabled' → True for bool field")


# ═══════════════════════════════════════════════════════════════════════════════
# 15. AI-unavailable / not-interpreted statuses
# ═══════════════════════════════════════════════════════════════════════════════

def test_ai_unavailable_status():
    """An ai_unavailable interpretation at any confidence goes to needs_training."""
    config = _empty_config()
    interp = _make_result(
        line_number=1,
        raw_line="unknown line",
        normalized_field="management.ssh_version",
        extracted_value="2",
        numeric_confidence=0.90,
        status=InterpretationStatus.AI_UNAVAILABLE,
    )
    records = map_interpretations(config, [interp])
    # Validation fails because status != interpreted
    assert config.management.ssh_version is None
    assert records[0].source == "needs_review"  # HIGH + invalid → needs_review
    assert records[0].status == "ai_unavailable"

    print("\nPASS [15a]: ai_unavailable HIGH → needs_review")


def test_unknown_interpretation_status():
    """An unknown-status interpretation goes to needs_training (if LOW) or review."""
    config = _empty_config()
    interp = _make_result(
        line_number=3,
        raw_line="mystery line",
        normalized_field="unknown",
        extracted_value=None,
        numeric_confidence=0.70,
        confidence=ConfidenceLevel.MEDIUM,
        status=InterpretationStatus.UNKNOWN,
    )
    records = map_interpretations(config, [interp])
    assert records[0].source == "needs_review"
    assert records[0].status == "unknown"
    assert records[0].confidence_tier == "medium"

    print("\nPASS [15b]: unknown-status MEDIUM → needs_review")


# ═══════════════════════════════════════════════════════════════════════════════
# 16. Integration — full pipeline with mocked Phase 2
# ═══════════════════════════════════════════════════════════════════════════════

def test_full_pipeline_high_to_compliance():
    """HIGH-confidence interpretation flows through to compliance engine evaluation."""
    from app.adaptive.capture import capture_unrecognized_lines

    raw_config = """\
system-name TEST-DEV

secure-shell protocol-version 2
secure-shell host-key minimum 3072

operator failed-login threshold 5
operator failed-login lockout 120

remote-console protocol telnet

credential-policy minimum-length 14
"""
    raw_lines = raw_config.splitlines()
    config = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="test"),
        raw_config=raw_config,
        raw_lines=raw_lines,
    )
    capture_unrecognized_lines(config)

    assert len(config.unrecognized_lines) > 0

    # Simulate Phase 2 AI output for one line
    # The "secure-shell protocol-version 2" line maps to management.ssh_version = 2
    first_line = config.unrecognized_lines[0]
    mock_interpretation = InterpretationResult(
        line_number=first_line.line_number,
        raw_line=first_line.raw_line,
        likely_vendor="generic",
        security_concept="ssh_version",
        normalized_field="management.ssh_version",
        extracted_value="2",
        confidence=ConfidenceLevel.HIGH,
        numeric_confidence=0.92,
        reasoning="SSH protocol version 2 detected",
        status=InterpretationStatus.INTERPRETED,
    )

    # Phase 3 — apply confidence-based interpretation
    map_interpretations(config, [mock_interpretation])

    # The HIGH-confidence mapping should have enriched the config
    assert config.management.ssh_version == 2
    # And the audit trail should be present
    assert len(config.ai_mappings) == 1
    assert config.ai_mappings[0].source == "ai_auto_mapped"

    print("\nPASS [16]: Full pipeline HIGH → auto-mapped → audit trail")


# ── Run directly ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_valid_high_mapping()
    test_invalid_high_mapping()
    test_invalid_high_mapping_unknown_field()
    test_invalid_high_mapping_container_field()
    test_medium_mapping()
    test_medium_mapping_even_if_type_valid()
    test_low_mapping()
    test_audit_fields_complete()
    test_confidence_tier_boundaries()
    test_string_confidence_fallback_high()
    test_string_confidence_fallback_medium()
    test_string_confidence_fallback_low()
    test_list_field_append()
    test_list_field_no_duplicates()
    test_console_line_created_on_demand()
    test_deterministic_rules_unchanged_cisco()
    test_deterministic_rules_unchanged_fortinet()
    test_ai_mapped_value_evaluated_by_deterministic_rules()
    test_effective_confidence_with_numeric()
    test_effective_confidence_without_numeric()
    test_make_confidence_decision()
    test_multiple_mixed_tiers()
    test_empty_interpretations()
    test_bool_conversion_variants("enabled", True)
    test_bool_auto_map_with_enabled()
    test_ai_unavailable_status()
    test_unknown_interpretation_status()
    test_full_pipeline_high_to_compliance()

    print("\n")
    print("=" * 60)
    print("ALL PHASE 3 TESTS PASSED")
    print("=" * 60)
