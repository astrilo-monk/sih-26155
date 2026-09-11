"""
End-to-end remediation pipeline tests.

Verifies the complete flow:
  vulnerable config -> scan -> remediate -> fixed config -> re-scan -> 0 findings / 100/100
"""

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.fortinet import FortinetParser
from app.analysis.engine import analyze
from app.remediation.engine import generate_remediation, apply_remediation

SAMPLES = Path(__file__).parent.parent.parent / "sample"


def _remediate_and_rescore(parser_cls, config_text):
    """Parse, analyze, remediate, re-parse, re-analyze. Return (original_result, fixed_result, fixed_text)."""
    parser = parser_cls()
    config = parser.parse(config_text)
    original = analyze(config)

    all_commands = []
    for finding in original.findings:
        remediation = generate_remediation(finding, [config])
        all_commands.append(remediation["commands"])

    modified = copy.deepcopy(config)
    for commands in all_commands:
        modified = apply_remediation(modified, commands)

    fixed_text = modified.raw_config
    reparsed = parser_cls().parse(fixed_text)
    fixed = analyze(reparsed)
    return original, fixed, fixed_text


def _assert_all_rules_remediated(original, fixed):
    """Verify every rule_id detected in the original is absent in the fixed result."""
    original_rules = {f.rule_id for f in original.findings}
    fixed_rules = {f.rule_id for f in fixed.findings}
    remaining = original_rules & fixed_rules
    assert not remaining, (
        f"These rules were NOT remediated: {remaining}\n"
        f"  Remaining findings:\n"
        + "\n".join(
            f"    {f.rule_id}: {f.title} ({f.severity.value})"
            for f in fixed.findings
            if f.rule_id in remaining
        )
    )


# ── Cisco configs ──────────────────────────────────────────────────────────


def test_remediate_01_multi_vulnerability():
    """01_cisco_multi_vulnerability.cfg: 15 findings -> 0 findings, score 100/100."""
    path = SAMPLES / "cisco" / "01_cisco_multi_vulnerability.cfg"
    config_text = path.read_text()
    original, fixed, _ = _remediate_and_rescore(CiscoIOSParser, config_text)

    assert original.total_findings == 15, f"Expected 15 findings, got {original.total_findings}"
    assert original.score == 0, f"Expected score 0, got {original.score}"
    assert fixed.score == 100, f"Expected score 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)


def test_remediate_02_secure_baseline():
    """02_cisco_secure_baseline.cfg: already mostly secure -> 0 findings, score 100/100."""
    path = SAMPLES / "cisco" / "02_cisco_secure_baseline.cfg"
    config_text = path.read_text()
    original, fixed, _ = _remediate_and_rescore(CiscoIOSParser, config_text)

    assert original.total_findings >= 1, f"Expected at least 1 finding, got {original.total_findings}"
    assert fixed.score == 100, f"Expected score 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)


def test_remediate_03_telnet_only():
    """03_cisco_telnet_only.cfg: 8 findings across all severities -> 0 findings, score 100/100."""
    path = SAMPLES / "cisco" / "03_cisco_telnet_only.cfg"
    config_text = path.read_text()
    original, fixed, _ = _remediate_and_rescore(CiscoIOSParser, config_text)

    assert original.score == 51, f"Expected score 51, got {original.score}"
    assert original.total_findings == 8, f"Expected 8 findings, got {original.total_findings}"

    expected_rules = {
        "MGMT-001", "MGMT-003", "MGMT-005", "MGMT-006",
        "MGMT-008", "MGMT-009", "LOG-001", "LOG-002",
    }
    actual_rules = {f.rule_id for f in original.findings}
    assert actual_rules == expected_rules, f"Expected rules {expected_rules}, got {actual_rules}"

    assert fixed.score == 100, f"Expected score 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)


def test_remediate_03_telnet_only_idempotent():
    """Remediation of 03_cisco_telnet_only.cfg is idempotent: re-remediating the fixed
    config should produce the same result."""
    path = SAMPLES / "cisco" / "03_cisco_telnet_only.cfg"
    config_text = path.read_text()

    _, fixed1, fixed_text1 = _remediate_and_rescore(CiscoIOSParser, config_text)
    _, fixed2, fixed_text2 = _remediate_and_rescore(CiscoIOSParser, fixed_text1)

    assert fixed1.score == 100, f"First pass score: {fixed1.score}"
    assert fixed2.score == 100, f"Second pass score: {fixed2.score}"
    assert fixed1.total_findings == 0, f"First pass findings: {fixed1.total_findings}"
    assert fixed2.total_findings == 0, f"Second pass findings: {fixed2.total_findings}"
    assert fixed_text1 == fixed_text2, "Idempotency failed: fixed configs differ after second pass"


def test_remediate_03_has_required_config_elements():
    """Verify the fixed 03 config contains all required remediation commands."""
    path = SAMPLES / "cisco" / "03_cisco_telnet_only.cfg"
    config_text = path.read_text()
    _, _, fixed_text = _remediate_and_rescore(CiscoIOSParser, config_text)

    required = [
        "transport input ssh",
        "aaa new-model",
        "aaa authentication login default local",
        "access-class MGMT_ACL in",
        "ip access-list standard MGMT_ACL",
        "exec-timeout 5 0",
        "logging host",
        "logging trap",
        "ntp server",
        "ntp authenticate",
        "banner login",
        "ip ssh version 2",
        "service password-encryption",
    ]
    for element in required:
        assert element in fixed_text, f"Missing required element in fixed config: {element}"

    forbidden = [
        "transport input telnet",
    ]
    for element in forbidden:
        assert element not in fixed_text, f"Forbidden element found in fixed config: {element}"


def test_no_duplicate_commands_in_fixed_config():
    """Verify no duplicate commands are injected by multiple remediation passes."""
    path = SAMPLES / "cisco" / "03_cisco_telnet_only.cfg"
    config_text = path.read_text()
    _, _, fixed_text = _remediate_and_rescore(CiscoIOSParser, config_text)

    lines = [l.strip() for l in fixed_text.splitlines() if l.strip() and not l.strip().startswith('!')]
    seen = {}
    duplicates = []
    for line in lines:
        if line in seen:
            seen[line] += 1
            if seen[line] == 2:
                duplicates.append(line)
        else:
            seen[line] = 1

    assert not duplicates, f"Duplicate commands found in fixed config: {duplicates}"


# ── Test fixture configs (existing test infrastructure) ────────────────────


def test_remediate_cisco_vulnerable_fixture():
    """The cisco_vulnerable.cfg fixture should also remediate cleanly."""
    fixtures = Path(__file__).parent / "fixtures"
    config_text = (fixtures / "cisco_vulnerable.cfg").read_text()
    original, fixed, _ = _remediate_and_rescore(CiscoIOSParser, config_text)

    assert original.total_findings >= 5, f"Expected >= 5 findings, got {original.total_findings}"
    assert fixed.score == 100, f"Expected score 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)
