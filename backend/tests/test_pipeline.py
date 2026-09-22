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
    assert any(f.rule_id == "BOUNDARY-001" for f in result.findings), "Cisco vulnerable should trigger BOUNDARY-001 (any-any ACL rule)"

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


FORTI_HEADER = "#config-version=FGT60D-6.00-FW-build0163-180510:opmode=0:vdom=0:user=admin\n#buildno=0163\n#global_vdom=1\n"


def test_fortinet_header_states_model_and_firmware_and_nothing_else():
    config = (FIXTURES / "fortinet_vulnerable.cfg").read_text()
    with_header = FortinetParser().parse(FORTI_HEADER + config)
    assert with_header.device.model == "FGT60D"
    assert with_header.device.os_version == "6.00 build0163"
    assert 1 in with_header.device.source_lines
    # identification only: the same controls decide the same way
    plain = FortinetParser().parse(config)
    outcome = lambda c: [(r.control_id, r.status) for r in analyze(c).device_results[0]]
    assert outcome(with_header) == outcome(plain)


def test_fortinet_without_header_states_no_model_or_firmware():
    body = (FIXTURES / "fortinet_vulnerable.cfg").read_text().split("config system global", 1)[1]
    config = FortinetParser().parse("config system global" + body)
    assert config.device.model is None and config.device.os_version is None
    # a header-shaped comment after the first statement is not the export header
    late = FortinetParser().parse("config system global\nend\n" + FORTI_HEADER)
    assert late.device.model is None
