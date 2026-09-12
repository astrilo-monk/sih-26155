"""
Phase 5 — Learned mapping database tests.

A  - Save mapping
B  - Retrieve mapping
C  - Match it on a later scan
D  - AI is not called for a reliable match
E  - Learn syntax from Vendor A
F  - Scan Vendor B with the same syntax (not siloed by vendor)
G  - Vendor A mapping surfaced as a candidate for similar Vendor B syntax
H  - Confirmed mapping cannot be silently overwritten
I  - Ambiguous mappings go to review
+  - pattern safety, permissions, disable, rejected lines, DB failure

All AI calls are mocked. Each test uses an isolated SQLite file (conftest).
"""

from unittest.mock import MagicMock

import pytest

from app.adaptive.capture import capture_unrecognized_lines
from app.adaptive.matcher import (
    EXTRACTION_CONSTANT,
    EXTRACTION_TEMPLATE_CAPTURE,
    PatternError,
    derive_pattern,
    match_pattern,
    validate_pattern,
)
from app.adaptive.service import AdaptiveService
from app.ai.interpretation_schemas import ConfidenceLevel, InterpretationResult, InterpretationStatus
from app.db.mappings import (
    LearnedMapping,
    MappingConflictError,
    MappingPermissionError,
    MappingRepository,
    MappingValidationError,
)
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor


def _config(text: str) -> NormalizedConfig:
    cfg = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="unknown"),
        raw_config=text,
        raw_lines=text.splitlines(),
    )
    capture_unrecognized_lines(cfg)
    return cfg


def _mapping(**overrides) -> LearnedMapping:
    values = dict(
        concept="ssh_protocol_version",
        normalized_field="management.ssh_version",
        vendor="vendor_a",
        command_pattern="secure-shell protocol-version {value}",
        extraction_method=EXTRACTION_TEMPLATE_CAPTURE,
        confirmed=True,
        example_line="secure-shell protocol-version 1",
    )
    values.update(overrides)
    return LearnedMapping(**values)


def _service(repo, results=None):
    interpreter = MagicMock(side_effect=lambda lines: results(lines) if results else [])
    return AdaptiveService(repository=repo, interpreter=interpreter, ai_available=lambda: True), interpreter


def _unknown_results(lines):
    return [
        InterpretationResult(
            line_number=ln.line_number,
            raw_line=ln.raw_line,
            likely_vendor="unknown",
            security_concept="unknown",
            normalized_field="unknown",
            extracted_value=None,
            confidence=ConfidenceLevel.LOW,
            numeric_confidence=0.2,
            reasoning="Not sure",
            status=InterpretationStatus.UNKNOWN,
        )
        for ln in lines
    ]


# A ───────────────────────────────────────────────────────────────────────────

def test_a_save_mapping():
    repo = MappingRepository()
    saved = repo.save_mapping(_mapping())

    assert saved.id is not None
    assert saved.confirmed is True
    assert saved.expected_value_type == "optional_int"
    assert saved.created_at and saved.updated_at


# B ───────────────────────────────────────────────────────────────────────────

def test_b_retrieve_mapping():
    repo = MappingRepository()
    saved = repo.save_mapping(_mapping())

    fetched = repo.get_mapping(saved.id)
    assert fetched == saved
    assert [m.id for m in repo.list_mappings()] == [saved.id]
    assert repo.find_matching_mappings("secure-shell protocol-version 2")[0].value == "2"


# C + D ───────────────────────────────────────────────────────────────────────

def test_c_d_match_on_later_scan_without_ai():
    repo = MappingRepository()
    repo.save_mapping(_mapping())

    cfg = _config("secure-shell protocol-version 1\n")
    service, interpreter = _service(repo)
    outcome = service.process(cfg)

    assert cfg.management.ssh_version == 1
    assert 1 in cfg.management.source_lines
    record = outcome.records[0]
    assert record.source == "learned_mapping"
    assert record.final_value == "1"
    assert record.mapping_id is not None
    assert record.raw_line == "secure-shell protocol-version 1"

    assert interpreter.call_count == 0
    assert outcome.ai_called is False


# E + F ───────────────────────────────────────────────────────────────────────

def test_e_f_mapping_learned_from_vendor_a_applies_to_vendor_b():
    repo = MappingRepository()
    repo.save_mapping(_mapping(
        concept="session_timeout",
        normalized_field="management.admin_timeout",
        vendor="vendor_a",
        command_pattern="admin idle-timeout {value}",
        example_line="admin idle-timeout 30",
    ))

    vendor_b = _config("admin idle-timeout 15\n")
    vendor_b.device.hostname = "vendor-b-device"
    service, interpreter = _service(repo)
    outcome = service.process(vendor_b)

    assert vendor_b.management.admin_timeout == 15
    assert outcome.records[0].source == "learned_mapping"
    assert interpreter.call_count == 0


# G ───────────────────────────────────────────────────────────────────────────

def test_g_similar_syntax_surfaces_candidate_and_falls_back_to_ai():
    repo = MappingRepository()
    saved = repo.save_mapping(_mapping(
        concept="session_timeout",
        normalized_field="management.admin_timeout",
        command_pattern="admin idle-timeout {value}",
        example_line="admin idle-timeout 30",
    ))

    cfg = _config("system admin idle-timeout minutes 10\n")
    service, interpreter = _service(repo, _unknown_results)
    outcome = service.process(cfg)

    # No reliable match → value not applied, AI consulted once
    assert cfg.management.admin_timeout is None
    assert interpreter.call_count == 1

    candidates = outcome.candidates[1]
    assert candidates[0].mapping.id == saved.id
    assert candidates[0].mapping.concept == "session_timeout"
    assert candidates[0].score >= 0.6


# H ───────────────────────────────────────────────────────────────────────────

def test_h_confirmed_mapping_cannot_be_silently_overwritten():
    repo = MappingRepository()
    original = repo.save_mapping(_mapping())

    with pytest.raises(MappingConflictError):
        repo.save_mapping(_mapping(
            normalized_field="management.ssh_timeout",
            concept="something_else",
            command_pattern="secure-shell   PROTOCOL-VERSION {value}",
        ))

    with pytest.raises(MappingPermissionError):
        repo.update_mapping(original.id, {"normalized_field": "management.ssh_timeout"}, actor="ai")
    with pytest.raises(MappingPermissionError):
        repo.disable_mapping(original.id, actor="ai")

    assert repo.get_mapping(original.id) == original
    assert len(repo.list_mappings()) == 1

    # Explicit administrator edits are allowed
    updated = repo.update_mapping(original.id, {"concept": "ssh_version"}, actor="admin")
    assert updated.concept == "ssh_version"


def test_ai_cannot_create_confirmed_mapping():
    with pytest.raises(MappingPermissionError):
        MappingRepository().save_mapping(_mapping(), actor="ai")


# I ───────────────────────────────────────────────────────────────────────────

def test_i_ambiguous_mappings_go_to_review():
    repo = MappingRepository()
    repo.save_mapping(_mapping(
        concept="ssh_host_key_minimum",
        normalized_field="management.ssh_version",
        command_pattern="ssh host-key minimum {value}",
        example_line="ssh host-key minimum 2048",
    ))
    repo.save_mapping(_mapping(
        concept="ssh_timeout",
        normalized_field="management.ssh_timeout",
        command_pattern="ssh {any} minimum {value}",
        example_line="ssh host-key minimum 2048",
    ))

    cfg = _config("ssh host-key minimum 2048\n")
    service, interpreter = _service(repo)
    outcome = service.process(cfg)

    record = outcome.records[0]
    assert record.source == "needs_review"
    assert record.confidence_tier == "ambiguous"
    assert cfg.management.ssh_version is None
    assert cfg.management.ssh_timeout is None
    assert interpreter.call_count == 0


def test_agreeing_mappings_are_not_ambiguous():
    repo = MappingRepository()
    repo.save_mapping(_mapping(command_pattern="ssh host-key minimum {value}", example_line="ssh host-key minimum 2"))
    repo.save_mapping(_mapping(command_pattern="ssh {any} minimum {value}", example_line="ssh host-key minimum 2"))

    cfg = _config("ssh host-key minimum 2\n")
    service, _ = _service(repo)
    assert service.process(cfg).records[0].source == "learned_mapping"
    assert cfg.management.ssh_version == 2


# Safety & lifecycle ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("pattern,method", [
    ("{value}", EXTRACTION_TEMPLATE_CAPTURE),
    ("ssh {value} {value}", EXTRACTION_TEMPLATE_CAPTURE),
    ("ssh version", EXTRACTION_TEMPLATE_CAPTURE),
    ("ssh {regex}", EXTRACTION_CONSTANT),
    ("ssh {value}", EXTRACTION_CONSTANT),
    ("", EXTRACTION_CONSTANT),
    ("ssh version", "regex"),
])
def test_invalid_patterns_rejected(pattern, method):
    with pytest.raises(PatternError):
        validate_pattern(pattern, method)


def test_regex_metacharacters_are_literal():
    assert match_pattern("secure.* {value}", EXTRACTION_TEMPLATE_CAPTURE, "secure-shell 2") == (False, None)
    assert match_pattern("secure.* {value}", EXTRACTION_TEMPLATE_CAPTURE, "secure.* 2") == (True, "2")


def test_invalid_field_or_value_not_persisted():
    repo = MappingRepository()
    with pytest.raises(MappingValidationError):
        repo.save_mapping(_mapping(normalized_field="interfaces[].name"))
    with pytest.raises(MappingValidationError):
        repo.save_mapping(_mapping(normalized_field="made.up_field"))
    with pytest.raises(MappingValidationError):
        repo.save_mapping(_mapping(example_line="secure-shell protocol-version modern"))
    with pytest.raises(MappingValidationError):
        repo.save_mapping(_mapping(
            normalized_field="management.telnet_enabled",
            command_pattern="remote-console protocol telnet",
            extraction_method=EXTRACTION_CONSTANT,
            constant_value="maybe",
            example_line="remote-console protocol telnet",
        ))
    assert repo.list_mappings(include_inactive=True) == []


def test_disabled_mapping_no_longer_matches():
    repo = MappingRepository()
    saved = repo.save_mapping(_mapping())
    repo.disable_mapping(saved.id, actor="admin")

    assert repo.find_matching_mappings("secure-shell protocol-version 1") == []
    assert repo.get_mapping(saved.id).active is False
    # A disabled pattern no longer blocks a replacement
    assert repo.save_mapping(_mapping()).id != saved.id


def test_derive_pattern():
    assert derive_pattern("audit-stream destination 10.1.1.1", "10.1.1.1") == (
        "audit-stream destination {value}", EXTRACTION_TEMPLATE_CAPTURE,
    )
    assert derive_pattern("remote-console protocol telnet", "true") == (
        "remote-console protocol telnet", EXTRACTION_CONSTANT,
    )


def test_rejected_line_is_not_sent_to_ai_again():
    repo = MappingRepository()
    repo.record_rejection("control-plane rate-guard 1200", vendor="unknown", reason="noise")

    cfg = _config("control-plane rate-guard 1200\n")
    service, interpreter = _service(repo, _unknown_results)
    outcome = service.process(cfg)

    assert interpreter.call_count == 0
    assert outcome.records[0].source == "rejected"


def test_mapping_store_failure_does_not_break_scan():
    broken = MagicMock()
    broken.list_mappings.side_effect = RuntimeError("database is locked")

    cfg = _config("secure-shell protocol-version 1\n")
    service, interpreter = _service(broken, _unknown_results)
    outcome = service.process(cfg)

    assert interpreter.call_count == 1
    assert outcome.records[0].source == "needs_training"


def test_learned_value_does_not_overwrite_parser_value():
    repo = MappingRepository()
    repo.save_mapping(_mapping())

    cfg = _config("secure-shell protocol-version 1\n")
    cfg.management.ssh_version = 2  # e.g. already set by a vendor parser
    service, _ = _service(repo)
    record = service.process(cfg).records[0]

    assert cfg.management.ssh_version == 2
    assert record.source == "needs_review"
    assert "conflicts" in record.reason
