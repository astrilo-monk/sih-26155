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


# ── Regression tests: previously failing Cisco configs ─────────────────────


TEST_CONFIGS = SAMPLES / "cisco" / "cisco_netaudit_test_configs"


def test_regression_00_all_test_configs():
    """00_ALL_TEST_CONFIGS.cfg: composite config with 14 sub-configs.
    Previously failed: MGMT-001 (telnet), MGMT-003 (access), MGMT-006 (timeout)."""
    path = TEST_CONFIGS / "00_ALL_TEST_CONFIGS.cfg"
    if not path.exists():
        return  # skip if test configs not present
    config_text = path.read_text()
    original, fixed, _ = _remediate_and_rescore(CiscoIOSParser, config_text)

    assert original.total_findings >= 1
    assert fixed.score == 100, f"Expected 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)


def test_regression_03_weak_passwords():
    """03_weak_passwords.cfg: Previously failed: MGMT-006 (timeout)."""
    path = TEST_CONFIGS / "03_weak_passwords.cfg"
    if not path.exists():
        return
    config_text = path.read_text()
    original, fixed, _ = _remediate_and_rescore(CiscoIOSParser, config_text)

    assert fixed.score == 100, f"Expected 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)


def test_regression_07_permissive_acl():
    """07_permissive_acl.cfg: Previously failed: BOUNDARY-003 (CDP)."""
    path = TEST_CONFIGS / "07_permissive_acl.cfg"
    if not path.exists():
        return
    config_text = path.read_text()
    original, fixed, _ = _remediate_and_rescore(CiscoIOSParser, config_text)

    assert fixed.score == 100, f"Expected 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)


def test_regression_11_ipv6_acl_edge():
    """11_ipv6_acl_edge.cfg: Previously failed: BOUNDARY-003 (CDP)."""
    path = TEST_CONFIGS / "11_ipv6_acl_edge.cfg"
    if not path.exists():
        return
    config_text = path.read_text()
    original, fixed, _ = _remediate_and_rescore(CiscoIOSParser, config_text)

    assert fixed.score == 100, f"Expected 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)


def test_regression_14_ssh_misconfigured():
    """14_ssh_misconfigured.cfg: Previously failed: MGMT-001, MGMT-003, MGMT-006.
    Config has 'transport input ssh telnet' (reversed order)."""
    path = TEST_CONFIGS / "14_ssh_misconfigured.cfg"
    if not path.exists():
        return
    config_text = path.read_text()
    original, fixed, fixed_text = _remediate_and_rescore(CiscoIOSParser, config_text)

    assert fixed.score == 100, f"Expected 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)
    # Verify telnet was removed even with reversed order
    assert "transport input ssh telnet" not in fixed_text
    assert "transport input telnet ssh" not in fixed_text


def test_regression_test_cfg_no_end_marker():
    """test.cfg: Previously failed because it has no 'end' marker,
    so global configs (AAA, logging, NTP, banner) were never injected."""
    path = SAMPLES / "cisco" / "test.cfg"
    config_text = path.read_text()
    original, fixed, fixed_text = _remediate_and_rescore(CiscoIOSParser, config_text)

    assert fixed.score == 100, f"Expected 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)
    # Verify an 'end' marker was added
    assert "end" in fixed_text.splitlines()


# ── Regression tests: previously failing Fortinet configs ──────────────────


def test_regression_fortinet_vulnerable_fixture():
    """fortinet_vulnerable.cfg: Previously failed: MGMT-004 (SNMP),
    BOUNDARY-001 (firewall), LOG-001 (syslog), LOG-002 (NTP auth).
    Cisco commands were injected into FortiGate config."""
    fixtures = Path(__file__).parent / "fixtures"
    config_text = (fixtures / "fortinet_vulnerable.cfg").read_text()
    original, fixed, fixed_text = _remediate_and_rescore(FortinetParser, config_text)

    assert original.total_findings >= 10, f"Expected >= 10 findings, got {original.total_findings}"
    assert fixed.score == 100, f"Expected 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)

    # Verify no Cisco commands leaked into Fortinet config
    assert "ip ssh version" not in fixed_text
    assert "aaa new-model" not in fixed_text
    assert "logging host" not in fixed_text
    assert "banner login" not in fixed_text


def test_regression_fortigate_vulnerable_sample():
    """04_fortigate_vulnerable.cfg: Same issue as fortinet_vulnerable.cfg."""
    path = SAMPLES / "frontinet" / "04_fortigate_vulnerable.cfg"
    config_text = path.read_text()
    original, fixed, _ = _remediate_and_rescore(FortinetParser, config_text)

    assert original.total_findings >= 10
    assert fixed.score == 100, f"Expected 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)


def test_regression_fortinet_demo_vulnerable():
    """fortinet_demo_vulnerable.cfg: Same issue as fortinet_vulnerable.cfg."""
    path = SAMPLES / "frontinet" / "fortinet_demo_vulnerable.cfg"
    config_text = path.read_text()
    original, fixed, _ = _remediate_and_rescore(FortinetParser, config_text)

    assert original.total_findings >= 10
    assert fixed.score == 100, f"Expected 100, got {fixed.score}"
    assert fixed.total_findings == 0, f"Expected 0 findings, got {fixed.total_findings}"
    _assert_all_rules_remediated(original, fixed)


def test_fortinet_snmp_community_removed():
    """Verify default SNMP community 'public' is commented out in fixed Fortinet config."""
    fixtures = Path(__file__).parent / "fixtures"
    config_text = (fixtures / "fortinet_vulnerable.cfg").read_text()
    _, _, fixed_text = _remediate_and_rescore(FortinetParser, config_text)

    # The default community should be commented out
    assert '# set name "public"' in fixed_text


def test_fortinet_syslog_enabled():
    """Verify syslog is enabled with a server in fixed Fortinet config."""
    fixtures = Path(__file__).parent / "fixtures"
    config_text = (fixtures / "fortinet_vulnerable.cfg").read_text()
    _, fixed, fixed_text = _remediate_and_rescore(FortinetParser, config_text)

    assert "set status enable" in fixed_text
    assert 'set server "10.0.0.100"' in fixed_text or 'set server "10.0.0.50"' in fixed_text


def test_fortinet_ntp_auth_enabled():
    """Verify NTP authentication is enabled in fixed Fortinet config."""
    fixtures = Path(__file__).parent / "fixtures"
    config_text = (fixtures / "fortinet_vulnerable.cfg").read_text()
    _, fixed, _ = _remediate_and_rescore(FortinetParser, config_text)

    # LOG-002 should not be in findings
    ntp_findings = [f for f in fixed.findings if f.rule_id == "LOG-002"]
    assert len(ntp_findings) == 0, f"NTP finding still present: {ntp_findings}"


def test_fortinet_firewall_restricted():
    """Verify overly permissive firewall policies are restricted in fixed Fortinet config."""
    fixtures = Path(__file__).parent / "fixtures"
    config_text = (fixtures / "fortinet_vulnerable.cfg").read_text()
    _, fixed, fixed_text = _remediate_and_rescore(FortinetParser, config_text)

    # BOUNDARY-001 should not be in findings
    fw_findings = [f for f in fixed.findings if f.rule_id == "BOUNDARY-001"]
    assert len(fw_findings) == 0, f"Firewall finding still present: {fw_findings}"

    # Verify 'all' is no longer used for srcaddr
    assert 'set srcaddr "all"' not in fixed_text


# ── Universal invariant test ──────────────────────────────────────────────


def test_all_known_vendor_configs_remediate_to_100():
    """
    Universal remediation invariant:
    For every known-vendor config with findings, remediation must
    produce a config that scores 100/100 with 0 findings on rescan.
    """
    import os
    from app.parsers.detector import detect_vendor
    from app.models.normalized import Vendor

    config_dirs = [
        SAMPLES / "cisco",
        SAMPLES / "frontinet",
        Path(__file__).parent / "fixtures",
    ]

    failures = []
    tested = 0

    for config_dir in config_dirs:
        if not config_dir.exists():
            continue
        for cfg_file in sorted(config_dir.rglob("*.cfg")):
            if "unknown" in cfg_file.name.lower():
                continue
            config_text = cfg_file.read_text()
            vendor = detect_vendor(config_text)
            if vendor == Vendor.UNKNOWN:
                continue

            parser_cls = CiscoIOSParser if vendor == Vendor.CISCO_IOS else FortinetParser
            original, fixed, _ = _remediate_and_rescore(parser_cls, config_text)

            if original.total_findings == 0:
                continue  # Already clean, nothing to test

            tested += 1
            if fixed.total_findings > 0:
                remaining = [f"{f.rule_id}: {f.title}" for f in fixed.findings]
                failures.append(
                    f"{cfg_file.name}: score={fixed.score}/100, "
                    f"remaining={remaining}"
                )

    assert tested >= 10, f"Expected to test at least 10 configs, only tested {tested}"
    assert not failures, (
        f"{len(failures)} config(s) failed remediation invariant:\n"
        + "\n".join(f"  - {f}" for f in failures)
    )


# ── Regression tests: specific bug fixes ──────────────────────────────────


def test_bug1_remove_config_line_exact_matching():
    """BUG #1: _remove_config_line used substring matching, causing false
    positive removals (e.g., 'snmp-server community public' also matched
    'snmp-server community public2'). Fixed to use exact line matching."""
    cisco_config = """
hostname TEST
!
snmp-server community public RO
snmp-server community public2 RO
snmp-server community management RW
!
end
"""
    original, fixed, fixed_text = _remediate_and_rescore(CiscoIOSParser, cisco_config)

    # public2 should NOT be removed (it's not a default community)
    assert 'snmp-server community public2' in fixed_text
    # public should be removed
    assert 'snmp-server community public RO' not in fixed_text
    # management RW (no ACL) should be commented out
    assert 'snmp-server community management RW (removed - no ACL)' in fixed_text
    assert '! snmp-server community management RW (removed - no ACL)' in fixed_text


def test_bug2_cisco_snmp_rw_no_acl_remediated():
    """BUG #2: MGMT-004 does not remediate non-default RW communities without ACLs.
    After fix, RW-without-ACL communities are removed."""
    cisco_config = """
hostname TEST-SNMP-HYBRID
!
snmp-server community public RO
snmp-server community management RW
!
line vty 0 4
 transport input ssh
!
end
"""
    original, fixed, fixed_text = _remediate_and_rescore(CiscoIOSParser, cisco_config)

    # MGMT-004 should be in original findings
    mgmt004_findings = [f for f in original.findings if f.rule_id == "MGMT-004"]
    assert len(mgmt004_findings) > 0, "Expected MGMT-004 finding for RW-without-ACL"

    # After remediation, MGMT-004 should be gone
    mgmt004_remaining = [f for f in fixed.findings if f.rule_id == "MGMT-004"]
    assert len(mgmt004_remaining) == 0, f"MGMT-004 still fires: {mgmt004_remaining}"
    assert fixed.score == 100


def test_bug3_fortinet_multi_interface_allowaccess():
    """BUG #3: FortiNet _replace_fortinet_set only replaced first occurrence of
    allowaccess. After fix, all WAN interfaces have management services removed."""
    fortinet_config = """
config system global
    set hostname "FW-01"
    set admintimeout 480
    set admin-ssh-v1 enable
    set pre-login-banner disable
end
config system interface
    edit "wan1"
        set allowaccess ping https ssh http telnet
        set role wan
    next
    edit "wan2"
        set allowaccess ping https ssh http telnet
        set role wan
    next
end
config system ntp
    set ntpsync enable
    config ntpserver
        edit 1
            set server "10.0.0.1"
            set authentication enable
        next
    end
end
config log syslogd setting
    set status disable
end
config system snmp community
    edit 1
        set name "public"
        set query-v2c-status enable
    next
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""
    original, fixed, fixed_text = _remediate_and_rescore(FortinetParser, fortinet_config)

    # Both interfaces should have allowaccess without management services
    assert 'set allowaccess ping https ssh http telnet' not in fixed_text
    # Verify ssh, https, http, telnet are removed from WAN interfaces
    for iface_name in ('"wan1"', '"wan2"'):
        # Find the allowaccess line for this interface
        lines = fixed_text.splitlines()
        for i, line in enumerate(lines):
            if f'edit {iface_name}' in line:
                # Check subsequent lines up to 'next'
                for j in range(i+1, min(i+5, len(lines))):
                    if 'allowaccess' in lines[j]:
                        allowaccess_line = lines[j].strip()
                        for bad_service in ('ssh', 'https', 'http', 'telnet'):
                            assert bad_service not in allowaccess_line, \
                                f"Service '{bad_service}' still in allowaccess for {iface_name}: {allowaccess_line}"
                        break
                    if 'next' in lines[j]:
                        break

    assert fixed.score == 100


def test_bug5_fortinet_ntp_block_absent():
    """BUG #5: FortiNet NTP remediation does not create NTP block when absent.
    After fix, a config system ntp block is created with authentication."""
    fortinet_config = """
config system global
    set hostname "FW-01"
    set admintimeout 480
    set admin-ssh-v1 enable
    set pre-login-banner disable
end
config system settings
    set ip-src-routing enable
end
config system interface
    edit "wan1"
        set allowaccess ping https ssh
        set role wan
    next
end
config log syslogd setting
    set status disable
end
config system snmp community
    edit 1
        set name "public"
    next
end
"""
    original, fixed, fixed_text = _remediate_and_rescore(FortinetParser, fortinet_config)

    # LOG-002 should not fire after remediation
    log002_findings = [f for f in fixed.findings if f.rule_id == "LOG-002"]
    assert len(log002_findings) == 0, f"LOG-002 still fires: {log002_findings}"

    # NTP block should have been created
    assert 'config system ntp' in fixed_text
    assert 'set authentication enable' in fixed_text
    assert 'ntp' in fixed_text.lower()
    assert fixed.score == 100


def test_bug6_fortinet_wan_ssh_https_removed():
    """BUG #6: FortiNet Phase 2 did not remove ssh/https from WAN allowaccess.
    After fix, all management services are removed from WAN interfaces."""
    fortinet_config = """
config system global
    set hostname "FW-01"
    set admintimeout 480
    set admin-ssh-v1 enable
    set pre-login-banner disable
end
config system settings
    set ip-src-routing enable
end
config system interface
    edit "wan1"
        set allowaccess ping https ssh
        set role wan
    next
    edit "wan2"
        set allowaccess ping https ssh
        set role wan
    next
end
config system ntp
    set ntpsync enable
    config ntpserver
        edit 1
            set server "10.0.0.1"
            set authentication enable
        next
    end
end
config log syslogd setting
    set status disable
end
config system snmp community
    edit 1
        set name "public"
    next
end
"""
    original, fixed, fixed_text = _remediate_and_rescore(FortinetParser, fortinet_config)

    # MGMT-003 should not fire
    mgmt003_findings = [f for f in fixed.findings if f.rule_id == "MGMT-003"]
    assert len(mgmt003_findings) == 0, f"MGMT-003 still fires: {mgmt003_findings}"
    assert fixed.score == 100


def test_bug7_cisco_crypto_strong_replacement_added():
    """BUG #7: CRYPTO-001 Cisco remediation removes weak ISAKMP policy but does not
    add a strong IKEv2 proposal. After fix, crypto ikev2 proposal is added."""
    cisco_config = """
hostname RTR
!
ip ssh version 2
!
crypto isakmp policy 10
 encr 3des
 hash md5
 authentication pre-share
 group 2
crypto isakmp key vpnsecret address 0.0.0.0 0.0.0.0
!
aaa new-model
aaa authentication login default local
!
line vty 0 4
 transport input ssh
 exec-timeout 5 0
 access-class MGMT_ACL in
!
ntp server 10.0.0.1
ntp authenticate
ntp authentication-key 1 md5 testkey
ntp trusted-key 1
!
ip http secure-server
service password-encryption
service timestamps log datetime msec
logging host 10.0.0.100
!
banner login ^
*** WARNING: Authorized access only ***
^
!
end
"""
    original, fixed, fixed_text = _remediate_and_rescore(CiscoIOSParser, cisco_config)

    # CRYPTO-001 should not fire after remediation
    crypto_findings = [f for f in fixed.findings if f.rule_id == "CRYPTO-001"]
    assert len(crypto_findings) == 0, f"CRYPTO-001 still fires: {crypto_findings}"

    # Strong IKEv2 proposal should have been added
    assert 'crypto ikev2 proposal STRONG_PROPOSAL' in fixed_text
    assert 'encryption aes-cbc-256' in fixed_text
    assert 'prf sha256' in fixed_text
    assert 'group 14' in fixed_text
    assert fixed.score == 100


def test_bug8_no_placeholders_in_fixed_config():
    """BUG #8: Template placeholders (<AUTH_PASS>, <PRIV_PASS>, <NTP_KEY>, <NEW_PASSWORD>)
    should never appear in the fixed config."""
    from app.parsers.detector import detect_vendor
    from app.models.normalized import Vendor

    config_dirs = [
        SAMPLES / "cisco",
        SAMPLES / "frontinet",
        Path(__file__).parent / "fixtures",
    ]

    placeholders = [
        '<AUTH_PASS>', '<PRIV_PASS>', '<NEW_PASSWORD>', '<NTP_KEY>',
        '{interface}', '{policy_id}', '{vpn_name}',
        'NTP_SECRET', 'AUTH_PASS', 'PRIV_PASS',
    ]

    for config_dir in config_dirs:
        if not config_dir.exists():
            continue
        for cfg_file in sorted(config_dir.rglob("*.cfg")):
            if "unknown" in cfg_file.name.lower():
                continue
            config_text = cfg_file.read_text()
            vendor = detect_vendor(config_text)
            if vendor == Vendor.UNKNOWN:
                continue

            parser_cls = CiscoIOSParser if vendor == Vendor.CISCO_IOS else FortinetParser
            _, _, fixed_text = _remediate_and_rescore(parser_cls, config_text)

            for placeholder in placeholders:
                assert placeholder not in fixed_text, (
                    f"Placeholder '{placeholder}' found in fixed config from {cfg_file.name}"
                )


def test_bug7_ike_version_2_enforced_fortinet():
    """BUG (CRYPTO-001 FortiNet): IKE version not remediated.
    After fix, ike-version 1 is upgraded to 2."""
    fortinet_config = """
config system global
    set hostname "FW-01"
    set admintimeout 480
    set admin-ssh-v1 enable
    set pre-login-banner disable
end
config system interface
    edit "wan1"
        set allowaccess ping ssh
        set role wan
    next
end
config system ntp
    set ntpsync enable
    config ntpserver
        edit 1
            set server "10.0.0.1"
            set authentication enable
        next
    end
end
config log syslogd setting
    set status disable
end
config system snmp community
    edit 1
        set name "public"
    next
end
config vpn ipsec phase1-interface
    edit "vpn1"
        set ike-version 1
        set proposal 3des-md5
        set dhgrp 2
    next
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
"""
    original, fixed, fixed_text = _remediate_and_rescore(FortinetParser, fortinet_config)

    # CRYPTO-001 should not fire
    crypto_findings = [f for f in fixed.findings if f.rule_id == "CRYPTO-001"]
    assert len(crypto_findings) == 0, f"CRYPTO-001 still fires: {crypto_findings}"

    # Strong proposal should be present
    assert 'aes256-sha256' in fixed_text
    assert 'set dhgrp 14' in fixed_text


def test_fortinet_idempotency_multiple_wan_interfaces():
    """Verify idempotency: re-remediating a fixed Fortinet config produces the same result."""
    fortinet_config = """
config system global
    set hostname "FW-01"
    set admintimeout 480
    set admin-ssh-v1 enable
    set pre-login-banner disable
end
config system settings
    set ip-src-routing enable
end
config system interface
    edit "wan1"
        set allowaccess ping https ssh http telnet
        set role wan
    next
    edit "wan2"
        set allowaccess ping https ssh http telnet
        set role wan
    next
end
config system snmp community
    edit 1
        set name "public"
    next
end
config log syslogd setting
    set status disable
end
"""
    _, fixed1, fixed_text1 = _remediate_and_rescore(FortinetParser, fortinet_config)
    _, fixed2, fixed_text2 = _remediate_and_rescore(FortinetParser, fixed_text1)

    assert fixed1.score == 100
    assert fixed2.score == 100
    assert fixed1.total_findings == 0
    assert fixed2.total_findings == 0
    assert fixed_text1 == fixed_text2

