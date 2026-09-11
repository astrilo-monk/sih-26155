"""
Phase 1 Adaptive Parsing Tests.

Tests:
- Unknown-vendor detection
- Novel security syntax detection
- Unknown security-line capture
- Irrelevant-line filtering
- Exact line numbers
- Surrounding context
- Vendor values
- Existing Cisco/FortiGate behavior
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.fortinet import FortinetParser
from app.parsers.detector import detect_vendor
from app.models.normalized import Vendor, NormalizedConfig, DeviceInfo
from app.adaptive.relevance import is_security_relevant
from app.adaptive.capture import capture_unrecognized_lines


# ============================================================
# HARD UNKNOWN-VENDOR CONFIGURATION
# ============================================================

UNKNOWN_VENDOR_CONFIG = """\
!
! ============================================================
! UNKNOWN VENDOR - HARD ADAPTIVE PARSING TEST
! ============================================================

system identity hostname EDGE-GW-07
system identity timezone Asia/Kolkata

!
! ---- Management Plane ----
!

administrative-access secure-shell state enabled
administrative-access secure-shell protocol-version 2
administrative-access secure-shell inactivity-limit 420
administrative-access secure-shell retry-limit 4

administrative-access legacy-console state disabled
administrative-access web-console http state disabled
administrative-access web-console https state enabled
administrative-access web-console session-limit 900

management-plane source-restriction enabled
management-plane allowed-network 10.20.0.0/16
management-plane allowed-network 172.20.50.0/24

!
! ---- Identity / AAA ----
!

identity-services centralized-authentication enabled
identity-services authentication-order radius local
identity-services authorization-order radius local
identity-services accounting session enabled

identity-services radius primary 10.20.10.10
identity-services radius primary secret ENC:9F8A72
identity-services radius secondary 10.20.10.11
identity-services radius secondary secret ENC:1AB82C

identity-services local-account netadmin privilege 15
identity-services local-account netadmin credential-hash $6$randomhash
identity-services local-account operator privilege 5

!
! ---- Monitoring / SNMP ----
!

telemetry management-protocol snmp state enabled
telemetry management-protocol snmp community monitor-read permission read-only
telemetry management-protocol snmp community legacy-write permission read-write
telemetry management-protocol snmp protocol-version 2c

telemetry management-protocol snmpv3 user audit-agent
telemetry management-protocol snmpv3 authentication sha256
telemetry management-protocol snmpv3 privacy aes256

!
! ---- Audit / Logging ----
!

audit-stream remote-collector 10.20.30.20
audit-stream remote-collector 10.20.30.21
audit-stream transport tls
audit-stream minimum-severity notice
audit-stream timestamp-format utc

audit-stream local-buffer enabled
audit-stream local-buffer-size 16384

!
! ---- Time Synchronization ----
!

time-synchronization primary-source 10.20.40.10
time-synchronization secondary-source 10.20.40.11
time-synchronization authentication enabled
time-synchronization authentication-key 17
time-synchronization trusted-source 10.20.40.0/24

!
! ---- Cryptography / VPN ----
!

secure-channel ipsec state enabled
secure-channel ipsec ike-version 2
secure-channel ipsec encryption aes-256
secure-channel ipsec integrity sha-256
secure-channel ipsec dh-group 14
secure-channel ipsec lifetime 3600

secure-channel proposal REMOTE-OFFICE
 secure-channel encryption aes256-gcm
 secure-channel integrity sha384
 secure-channel peer 198.51.100.25
 secure-channel authentication certificate

!
! ---- Firewall / Boundary ----
!

boundary-policy default-action deny
boundary-policy logging enabled
boundary-policy invalid-packet drop enabled

boundary-rule 100 source any destination any service ssh action allow log enabled
boundary-rule 110 source any destination any service telnet action allow log disabled
boundary-rule 120 source 10.20.0.0/16 destination any service https action allow
boundary-rule 130 source any destination any service any action deny

!
! ---- Network Protection ----
!

forwarding-protection source-routing state disabled
forwarding-protection directed-broadcast state disabled
forwarding-protection martian-source filtering enabled

neighbor-discovery cdp state disabled
neighbor-discovery lldp state disabled
neighbor-discovery external-advertisement state disabled

!
! ---- Interface Configuration ----
!

port ethernet0/0
 description "WAN uplink"
 address 203.0.113.10/30
 speed 1000
 duplex full

port ethernet0/1
 description "Internal users"
 address 10.20.1.1/24
 speed 1000
 duplex full

port ethernet0/2
 description "Management network"
 address 10.20.50.1/24
 speed 1000
 duplex full

!
! ---- Deliberately unfamiliar security syntax ----
!

secure-shell hardening profile strict
secure-shell cipher-policy modern
secure-shell host-key minimum 3072
secure-shell client-forwarding disabled

operator inactivity-lock 900
operator failed-login threshold 5
operator failed-login lockout 120

remote-console protocol telnet
remote-console exposure external
remote-console source-filter unrestricted

credential-policy minimum-length 14
credential-policy complexity required
credential-policy history-depth 12
credential-policy expiration 90

audit collector 10.20.60.10
audit collector protocol encrypted
audit collector verify-peer enabled

control-plane shield state enabled
control-plane shield rate-limit 1000
control-plane shield unauthorized-source drop

management-plane emergency-access enabled
management-plane emergency-access protocol legacy

!
! ---- Noise / structural syntax ----
!

object network INTERNAL-USERS
 address 10.20.1.0/24

object network MANAGEMENT
 address 10.20.50.0/24

routing static 0.0.0.0/0 next-hop 203.0.113.9
routing ospf process 100
routing ospf area 0

vlan 10 name USERS
vlan 20 name SERVERS
vlan 50 name MANAGEMENT

!
! End of test configuration
!
"""


# ============================================================
# ORIGINAL CISCO TEST CONFIG
# ============================================================

CISCO_CONFIG_WITH_UNRECOGNIZED = """!
version 15.2
service timestamps log datetime
!
hostname TEST-RTR
!
! This is a comment line - should not be captured
!
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
! Unrecognized security-relevant line
ip ssh pubkey-chain
  username admin
   key-string AAAAB3NzaC1yc2EAAAADAQABAAABAQC...
!
! Another unrecognized security line
radius-server host 10.0.0.1 auth-port 1812 acct-port 1813 key secretkey
!
interface GigabitEthernet0/0
 description WAN Interface
 ip address 203.0.113.2 255.255.255.252
!
! Irrelevant
 description This is just a description
!
 ip address 192.168.1.1 255.255.255.0
!
! Security-relevant
tacacs-server host 10.0.0.2 key tacacssecret
!
line vty 0 4
 exec-timeout 5 0
 transport input ssh
!
end
"""


# ============================================================
# FORTINET TEST CONFIG
# ============================================================

FORTINET_CONFIG_WITH_UNRECOGNIZED = """\
config system global
    set hostname TEST-FGT
    set admin-timeout 5
end

config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.252
        set allowaccess ping https ssh
    next
    edit "lan"
        set ip 192.168.1.1 255.255.255.0
        set allowaccess ping https ssh snmp
    next
end

config system admin
    edit "admin"
        set password ENC xxxxx
    next
end

config system snmp sysinfo
    set status enable
    set engine-id 000000000000000000000000
end
"""


# ============================================================
# 1. UNKNOWN VENDOR DETECTION
# ============================================================

def test_unknown_vendor_config():

    vendor = detect_vendor(UNKNOWN_VENDOR_CONFIG)

    print("\n========================================")
    print("UNKNOWN VENDOR TEST")
    print("========================================")
    print("Detected vendor:", vendor)

    assert str(vendor).lower() not in [
        "cisco_ios",
        "fortinet",
    ]

    print("PASS: Unknown vendor was not misidentified")


# ============================================================
# 2. HARD NOVEL SECURITY SYNTAX
# ============================================================

def test_unknown_vendor_security_lines():

    security_lines = [

        # Management
        "administrative-access secure-shell state enabled",
        "administrative-access secure-shell inactivity-limit 420",
        "management-plane source-restriction enabled",

        # AAA
        "identity-services centralized-authentication enabled",
        "identity-services authorization-order radius local",
        "identity-services radius primary 10.20.10.10",

        # Monitoring
        "telemetry management-protocol snmpv3 authentication sha256",

        # Logging
        "audit-stream transport tls",
        "audit-stream remote-collector 10.20.30.20",

        # Time
        "time-synchronization authentication enabled",

        # VPN
        "secure-channel ipsec ike-version 2",
        "secure-channel ipsec encryption aes-256",

        # Firewall
        "boundary-policy default-action deny",

        # Network protection
        "forwarding-protection source-routing state disabled",

        # Completely unfamiliar security terminology
        "secure-shell hardening profile strict",
        "secure-shell cipher-policy modern",
        "operator failed-login threshold 5",
        "credential-policy complexity required",
        "control-plane shield state enabled",
        "management-plane emergency-access protocol legacy",
    ]

    print("\n========================================")
    print("HARD SECURITY RELEVANCE TEST")
    print("========================================")

    for line in security_lines:

        result = is_security_relevant(line)

        print(
            f"[{'PASS' if result else 'FAIL'}] "
            f"{line}"
        )

        assert result, (
            f"Novel security syntax was rejected: {line}"
        )

    print("\nPASS: All hard security syntax detected")


# ============================================================
# 3. HARD IRRELEVANT SYNTAX
# ============================================================

def test_unknown_vendor_irrelevant_lines():

    irrelevant_lines = [

        'description "WAN uplink"',
        'description "Internal users"',
        'description "Management network"',

        "address 203.0.113.10/30",
        "address 10.20.1.1/24",
        "address 10.20.50.1/24",

        "speed 1000",
        "duplex full",

        "vlan 10 name USERS",
        "vlan 20 name SERVERS",
        "vlan 50 name MANAGEMENT",

        "routing static 0.0.0.0/0 next-hop 203.0.113.9",
        "routing ospf process 100",
        "routing ospf area 0",

        "object network INTERNAL-USERS",
        "object network MANAGEMENT",

        "network 10.20.1.0/24",
    ]

    print("\n========================================")
    print("HARD IRRELEVANT TEST")
    print("========================================")

    for line in irrelevant_lines:

        result = is_security_relevant(line)

        print(
            f"[{'FAIL' if result else 'PASS'}] "
            f"{line}"
        )

        assert not result, (
            f"Structural/network line incorrectly "
            f"classified as security relevant: {line}"
        )

    print("\nPASS: Structural noise correctly ignored")


# ============================================================
# 4. CAPTURE UNKNOWN SECURITY SYNTAX
# ============================================================

def test_unknown_vendor_capture():

    raw_lines = UNKNOWN_VENDOR_CONFIG.splitlines()

    normalized = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN),
        raw_config=UNKNOWN_VENDOR_CONFIG,
        raw_lines=raw_lines,
    )

    capture_unrecognized_lines(normalized)

    print("\n========================================")
    print("CAPTURED UNKNOWN SECURITY LINES")
    print("========================================")

    for line in normalized.unrecognized_lines:

        print(
            f"Line {line.line_number}: "
            f"{line.raw_line.strip()}"
        )

    print(
        "\nTotal captured:",
        len(normalized.unrecognized_lines)
    )

    assert len(normalized.unrecognized_lines) > 0

    captured_text = "\n".join(
        line.raw_line
        for line in normalized.unrecognized_lines
    ).lower()

    expected = [

        "secure-shell hardening",
        "secure-shell cipher-policy",
        "operator failed-login",
        "credential-policy complexity",
        "control-plane shield",
        "management-plane emergency-access",
        "identity-services centralized-authentication",
        "audit-stream transport",
        "secure-channel ipsec",
        "boundary-policy default-action",
    ]

    for expected_line in expected:

        assert expected_line.lower() in captured_text, (
            f"Expected security syntax was NOT captured: "
            f"{expected_line}"
        )

    print("\nPASS: Hard unknown security syntax captured")


# ============================================================
# 5. EXACT LINE NUMBER
# ============================================================

def test_exact_line_number():

    raw_lines = UNKNOWN_VENDOR_CONFIG.splitlines()

    normalized = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN),
        raw_config=UNKNOWN_VENDOR_CONFIG,
        raw_lines=raw_lines,
    )

    capture_unrecognized_lines(normalized)

    target = "secure-shell hardening profile strict"

    expected_line_number = None

    for i, line in enumerate(raw_lines):

        if target in line:

            expected_line_number = i + 1
            break

    assert expected_line_number is not None

    captured = [
        line
        for line in normalized.unrecognized_lines
        if target in line.raw_line
    ]

    assert len(captured) == 1

    assert captured[0].line_number == expected_line_number

    print(
        f"\nPASS: Exact line number = "
        f"{expected_line_number}"
    )


# ============================================================
# 6. CONTEXT
# ============================================================

def test_surrounding_context():

    raw_lines = UNKNOWN_VENDOR_CONFIG.splitlines()

    normalized = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN),
        raw_config=UNKNOWN_VENDOR_CONFIG,
        raw_lines=raw_lines,
    )

    capture_unrecognized_lines(normalized)

    target = "secure-shell hardening"

    captured = [
        line
        for line in normalized.unrecognized_lines
        if target in line.raw_line
    ]

    assert len(captured) == 1

    line = captured[0]

    assert len(line.context_before) > 0
    assert len(line.context_after) > 0

    print("\nPASS: Surrounding context captured")
    print("Context before:", line.context_before)
    print("Context after:", line.context_after)


# ============================================================
# 7. CISCO EXISTING BEHAVIOR
# ============================================================

def test_cisco_existing_behavior():

    parser = CiscoIOSParser()

    normalized = parser.parse(
        CISCO_CONFIG_WITH_UNRECOGNIZED
    )

    capture_unrecognized_lines(normalized)

    captured_lines = [
        line.raw_line.strip()
        for line in normalized.unrecognized_lines
    ]

    assert any(
        "ip ssh pubkey-chain" in line
        for line in captured_lines
    )

    assert any(
        "radius-server host" in line
        for line in captured_lines
    )

    assert any(
        "tacacs-server host" in line
        for line in captured_lines
    )

    assert not any(
        "description This is just a description" in line
        for line in captured_lines
    )

    assert not any(
        "ip address 192.168.1.1" in line
        for line in captured_lines
    )

    print("\nPASS: Existing Cisco adaptive behavior preserved")


# ============================================================
# 8. FORTINET EXISTING BEHAVIOR
# ============================================================

def test_fortinet_existing_behavior():

    parser = FortinetParser()

    normalized = parser.parse(
        FORTINET_CONFIG_WITH_UNRECOGNIZED
    )

    capture_unrecognized_lines(normalized)

    for line in normalized.unrecognized_lines:

        assert line.vendor == "fortinet"

    print("\nPASS: FortiGate adaptive behavior preserved")


# ============================================================
# 9. VENDOR VALUES
# ============================================================

def test_vendor_values():

    unknown = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN),
        raw_config="ssh custom-setting enabled",
        raw_lines=[
            "ssh custom-setting enabled"
        ],
    )

    capture_unrecognized_lines(unknown)

    assert len(unknown.unrecognized_lines) > 0

    for line in unknown.unrecognized_lines:

        assert line.vendor == "unknown"

    print("\nPASS: Unknown vendor value preserved")


# ============================================================
# 10. DIRECT RELEVANCE TEST
# ============================================================

def test_relevance_filter_directly():

    security_lines = [

        "ip ssh version 2",
        "aaa authentication login default group radius",
        "snmp-server community public RO",
        "logging host 10.0.0.1",
        "banner login Warning",
        "crypto isakmp policy 10",
        "access-list 100 permit ip any any",
        "ip ssh pubkey-chain",
        "radius-server host 10.0.0.1",
        "tacacs-server host 10.0.0.1",

    ]

    for line in security_lines:

        assert is_security_relevant(line) is True

    irrelevant_lines = [

        "!",
        "# comment",
        "description WAN Interface",
        "ip address 192.168.1.1 255.255.255.0",
        "duplex auto",
        "speed 1000",
        "vlan 100",
        "router ospf 1",
        "network 192.168.1.0 0.0.0.255 area 0",

    ]

    for line in irrelevant_lines:

        assert is_security_relevant(line) is False

    print("\nPASS: Original relevance tests")


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    test_unknown_vendor_config()
    test_unknown_vendor_security_lines()
    test_unknown_vendor_irrelevant_lines()
    test_unknown_vendor_capture()
    test_exact_line_number()
    test_surrounding_context()
    test_cisco_existing_behavior()
    test_fortinet_existing_behavior()
    test_vendor_values()
    test_relevance_filter_directly()

    print("\n")
    print("============================================")
    print("ALL HARD PHASE 1 TESTS PASSED")
    print("============================================")