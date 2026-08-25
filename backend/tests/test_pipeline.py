"""
Core pipeline test: parse a vulnerable config and verify findings are detected.
"""

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.parsers.detector import detect_vendor
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.fortinet import FortinetParser
from app.analysis.engine import analyze
from app.models.normalized import Vendor

FIXTURES = Path(__file__).parent / "fixtures"


def test_cisco_vendor_detection():
    config = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    assert detect_vendor(config) == Vendor.CISCO_IOS


def test_fortinet_vendor_detection():
    config = (FIXTURES / "fortinet_vulnerable.cfg").read_text()
    assert detect_vendor(config) == Vendor.FORTINET


def test_cisco_parser_basics():
    config = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    parser = CiscoIOSParser()
    result = parser.parse(config)

    assert result.device.vendor == Vendor.CISCO_IOS
    assert result.device.hostname == "CORP-RTR-01"
    assert len(result.raw_lines) > 0


def test_fortinet_parser_basics():
    config = (FIXTURES / "fortinet_vulnerable.cfg").read_text()
    parser = FortinetParser()
    result = parser.parse(config)

    assert result.device.vendor == Vendor.FORTINET
    assert len(result.raw_lines) > 0


def test_cisco_vulnerable_finds_issues():
    """The vulnerable Cisco config should trigger multiple findings."""
    config = (FIXTURES / "cisco_vulnerable.cfg").read_text()
    parser = CiscoIOSParser()
    normalized = parser.parse(config)
    result = analyze(normalized)

    assert result.score < 80, f"Score should be low for vulnerable config, got {result.score}"
    assert result.total_findings >= 5, f"Expected at least 5 findings, got {result.total_findings}"
    assert result.critical_count >= 1, "Expected at least 1 critical finding"

    rule_ids = [f.rule_id for f in result.findings]
    print(f"\nCisco vulnerable: score={result.score}, findings={result.total_findings}")
    print(f"  Critical: {result.critical_count}, High: {result.high_count}, "
          f"Medium: {result.medium_count}, Low: {result.low_count}")
    for f in result.findings:
        print(f"  [{f.severity.value.upper():8}] {f.rule_id}: {f.title}")


def test_cisco_secure_has_fewer_issues():
    """The secure Cisco config should have significantly fewer findings."""
    config = (FIXTURES / "cisco_secure.cfg").read_text()
    parser = CiscoIOSParser()
    normalized = parser.parse(config)
    result = analyze(normalized)

    assert result.score > 70, f"Score should be high for secure config, got {result.score}"

    print(f"\nCisco secure: score={result.score}, findings={result.total_findings}")
    for f in result.findings:
        print(f"  [{f.severity.value.upper():8}] {f.rule_id}: {f.title}")


def test_fortinet_vulnerable_finds_issues():
    """The vulnerable FortiGate config should trigger multiple findings."""
    config = (FIXTURES / "fortinet_vulnerable.cfg").read_text()
    parser = FortinetParser()
    normalized = parser.parse(config)
    result = analyze(normalized)

    assert result.score < 80, f"Score should be low for vulnerable config, got {result.score}"
    assert result.total_findings >= 3, f"Expected at least 3 findings, got {result.total_findings}"

    print(f"\nFortiGate vulnerable: score={result.score}, findings={result.total_findings}")
    print(f"  Critical: {result.critical_count}, High: {result.high_count}, "
          f"Medium: {result.medium_count}, Low: {result.low_count}")
    for f in result.findings:
        print(f"  [{f.severity.value.upper():8}] {f.rule_id}: {f.title}")


def test_fortinet_secure_has_fewer_issues():
    """The secure FortiGate config should have significantly fewer findings."""
    config = (FIXTURES / "fortinet_secure.cfg").read_text()
    parser = FortinetParser()
    normalized = parser.parse(config)
    result = analyze(normalized)

    assert result.score > 70, f"Score should be high for secure config, got {result.score}"

    print(f"\nFortiGate secure: score={result.score}, findings={result.total_findings}")
    for f in result.findings:
        print(f"  [{f.severity.value.upper():8}] {f.rule_id}: {f.title}")


def test_scoring_math():
    """Verify score calculation is correct."""
    from app.models.findings import Finding, Severity
    from app.analysis.scoring import calculate_score

    findings = [
        Finding(rule_id="TEST", title="test", severity=Severity.CRITICAL,
                description="test"),
        Finding(rule_id="TEST", title="test", severity=Severity.HIGH,
                description="test"),
        Finding(rule_id="TEST", title="test", severity=Severity.MEDIUM,
                description="test"),
        Finding(rule_id="TEST", title="test", severity=Severity.LOW,
                description="test"),
    ]
    # 12 + 6 + 3 + 1 = 22, so score = 78
    assert calculate_score(findings) == 78


def test_empty_config_detection():
    """Empty or garbage text should return UNKNOWN vendor."""
    assert detect_vendor("") == Vendor.UNKNOWN
    assert detect_vendor("hello world this is not a config") == Vendor.UNKNOWN
