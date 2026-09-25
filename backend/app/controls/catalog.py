"""
Control catalog -the security questions the auditor answers.

One entry per control (ids kept from the original rules). Each control states
its question, decision kind, the highest severity a FAIL can have, the
remediation template keys, the security-fact predicates it needs, and its
framework mappings with the exact framework version.

Mapping sources (verified 2026-09-13):

* NIST SP 800-53 Rev. 5 -official OSCAL catalog, release 5.2.0
  (github.com/usnistgov/oscal-content). Every id below exists with this title
  and none is withdrawn. AU-8(1), formerly cited for NTP authentication, is
  withdrawn in Rev. 5 and moved to SC-45(1).
* DISA STIG -requirement ids and titles from the Network Device Management SRG
  (vendor-agnostic; the product STIGs derive their V-ids from these SRG ids).
  Only requirements whose wording a control actually answers are mapped.
* ISO/IEC 27001:2022 Annex A -control ids and titles as published in the
  standard. Annex A controls are organisational; a device-configuration control
  is evidence towards one, never proof that the Annex A control is met.
* CIS Benchmarks -item ids and titles as published in Tenable's audit files
  for the named benchmark version and profile level. Only items confirmed for
  that exact benchmark version are listed: a control without a verified item
  has no CIS mapping rather than a guessed one. CIS items are product-specific
  and are only attached to findings for that vendor.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.facts import predicates as P
from app.models.findings import Severity
from app.models.normalized import Vendor


class ControlKind(str, Enum):
    PROHIBITION = "prohibition"  # an insecure setting must be off
    REQUIREMENT = "requirement"  # a security setting must be present
    THRESHOLD = "threshold"      # a value must stay within a bound
    RELATIONAL = "relational"    # objects must reference each other correctly


NIST = "NIST_800_53"
NIST_VERSION = "SP 800-53 Rev. 5 (5.2.0)"
CIS = "CIS"
CIS_IOS_XE_L1 = "Cisco IOS XE 17.x Benchmark v2.2.1 (Level 1)"
CIS_IOS_XE_L2 = "Cisco IOS XE 17.x Benchmark v2.2.1 (Level 2)"
CIS_IOS_XE_210_L1 = "Cisco IOS XE 17.x Benchmark v2.1.0 (Level 1)"
CIS_FORTIGATE_L1 = "FortiGate 7.4.x Benchmark v1.0.1 (Level 1)"
CIS_FORTIGATE_L2 = "FortiGate 7.4.x Benchmark v1.0.1 (Level 2)"
STIG = "DISA_STIG"
STIG_NDM = "Network Device Management SRG V4"
ISO = "ISO_27001"
ISO_VERSION = "ISO/IEC 27001:2022 Annex A"


@dataclass(frozen=True)
class Mapping:
    framework: str
    version: str
    requirement_id: str
    title: str
    # Set for product-specific benchmark items; None applies to every vendor
    vendor: Optional[Vendor] = None


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    question: str
    kind: ControlKind
    # Highest severity a FAIL of this control can have
    severity: Severity
    category: str
    mappings: tuple[Mapping, ...]
    remediation_keys: tuple[str, ...]
    # Security-fact predicates the control consumes
    needs: tuple[str, ...] = ()
    # The control asks about an optional feature (a VPN): a device that does not configure it at all
    # is N/A, not undecided. Only a confirmed vendor can prove the absence.
    optional_feature: str = ""


def _nist(requirement_id: str, title: str) -> Mapping:
    return Mapping(NIST, NIST_VERSION, requirement_id, title)


def _cis_ios(requirement_id: str, title: str, version: str = CIS_IOS_XE_L1) -> Mapping:
    return Mapping(CIS, version, requirement_id, title, Vendor.CISCO_IOS)


def _cis_fortigate(requirement_id: str, title: str, version: str = CIS_FORTIGATE_L1) -> Mapping:
    return Mapping(CIS, version, requirement_id, title, Vendor.FORTINET)


def _stig(requirement_id: str, title: str) -> Mapping:
    return Mapping(STIG, STIG_NDM, requirement_id, title)


def _iso(requirement_id: str, title: str) -> Mapping:
    return Mapping(ISO, ISO_VERSION, requirement_id, title)


_CONTROLS = (
    Control(
        control_id="MGMT-001",
        title="Insecure Management Protocol (Telnet) Enabled",
        question="Is cleartext Telnet disabled for remote management?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.CRITICAL,
        category="management",
        mappings=(
            _nist("AC-17(2)", "Protection of Confidentiality and Integrity Using Encryption"),
            _nist("SC-8", "Transmission Confidentiality and Integrity"),
            _cis_ios("1.2.2", "Set 'transport input ssh' for 'line vty' connections"),
            _cis_fortigate("2.4.5", "Ensure only encrypted access channels are enabled"),
            _stig("SRG-APP-000142-NDM-000245",
                "The network device must be configured to prohibit the use of all unnecessary and nonsecure "
                "functions, ports, protocols, and services"),
            _stig("SRG-APP-000412-NDM-000331",
                "The network device must be configured to implement cryptographic mechanisms to protect the "
                "confidentiality of remote maintenance sessions"),
            _iso("A.8.20", "Networks security"),
            _iso("A.8.24", "Use of cryptography"),
            _iso("A.5.14", "Information transfer"),
        ),
        remediation_keys=("MGMT-001",),
        needs=(P.PROTOCOL_ENABLED,),
    ),
    Control(
        control_id="MGMT-002",
        title="Insecure HTTP Management Enabled",
        question="Is cleartext HTTP management disabled?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.HIGH,
        category="management",
        mappings=(
            _nist("AC-17(2)", "Protection of Confidentiality and Integrity Using Encryption"),
            _nist("SC-8", "Transmission Confidentiality and Integrity"),
            _cis_fortigate("1.3", "Disable all management related services on WAN port"),
            _cis_fortigate("2.4.5", "Ensure only encrypted access channels are enabled"),
            _stig("SRG-APP-000142-NDM-000245",
                "The network device must be configured to prohibit the use of all unnecessary and nonsecure "
                "functions, ports, protocols, and services"),
            _stig("SRG-APP-000412-NDM-000331",
                "The network device must be configured to implement cryptographic mechanisms to protect the "
                "confidentiality of remote maintenance sessions"),
            _iso("A.8.20", "Networks security"),
            _iso("A.8.24", "Use of cryptography"),
        ),
        remediation_keys=("MGMT-002",),
        needs=(P.PROTOCOL_ENABLED,),
    ),
    Control(
        control_id="MGMT-003",
        title="Unrestricted Management Access",
        question="Is management access restricted to trusted sources?",
        kind=ControlKind.RELATIONAL,
        severity=Severity.CRITICAL,
        category="management",
        mappings=(
            _nist("AC-3", "Access Enforcement"),
            _nist("AC-17(1)", "Monitoring and Control"),
            _nist("SC-7", "Boundary Protection"),
            _cis_ios("1.2.4", "Create 'access-list' for use with 'line vty'"),
            _cis_ios("1.2.5", "Set 'access-class' for 'line vty'"),
            _cis_fortigate("1.3", "Disable all management related services on WAN port"),
            _cis_fortigate("2.4.2", "Ensure all the login accounts having specific trusted hosts enabled"),
            _stig("SRG-APP-000033-NDM-000212",
                "The network device must be configured to enforce approved authorizations for logical access "
                "to information and system resources"),
            _iso("A.5.15", "Access control"),
            _iso("A.8.3", "Information access restriction"),
            _iso("A.8.20", "Networks security"),
        ),
        remediation_keys=("MGMT-003",),
        needs=(P.SOURCE_RESTRICTED,),
    ),
    Control(
        control_id="MGMT-004",
        title="Weak or Default SNMP Community Strings",
        question="Are SNMP communities free of default strings and unrestricted write access?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.CRITICAL,
        category="management",
        mappings=(
            _nist("IA-5", "Authenticator Management"),
            _nist("AC-3", "Access Enforcement"),
            _cis_ios("1.5.2", "Unset 'private' for 'snmp-server community'"),
            _cis_ios("1.5.3", "Unset 'public' for 'snmp-server community'"),
            _cis_ios("1.5.4", "Do not set 'RW' for any 'snmp-server community'"),
            _cis_ios("1.5.5", "Set the ACL for each 'snmp-server community'"),
            _cis_fortigate("2.3.1", "Ensure only SNMPv3 is enabled"),
            _stig("SRG-APP-000142-NDM-000245",
                "The network device must be configured to prohibit the use of all unnecessary and nonsecure "
                "functions, ports, protocols, and services"),
            _iso("A.5.17", "Authentication information"),
            _iso("A.8.21", "Security of network services"),
        ),
        remediation_keys=("MGMT-004",),
        needs=(P.SNMP_COMMUNITY,),
    ),
    Control(
        control_id="MGMT-005",
        title="Plaintext or Weakly Encrypted Passwords",
        question="Are stored passwords protected with strong, non-reversible encoding?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.CRITICAL,
        category="management",
        mappings=(
            _nist("IA-5", "Authenticator Management"),
            _nist("IA-5(1)", "Password-based Authentication"),
            _cis_ios("1.4.1", "Set 'password' for 'enable secret'"),
            _cis_ios("1.4.2", "Enable 'service password-encryption'"),
            _cis_ios("1.4.3", "Set 'username secret' for all local users"),
            _stig("SRG-APP-000172-NDM-000259",
                "The network device must be configured to use an encrypted representation of passwords"),
            _iso("A.5.17", "Authentication information"),
            _iso("A.8.5", "Secure authentication"),
        ),
        remediation_keys=("MGMT-005",),
        needs=(P.PASSWORD_STORAGE, P.PASSWORD_ENCRYPTION_SERVICE),
    ),
    Control(
        control_id="MGMT-006",
        title="Missing or Disabled Session Timeout",
        question="Do idle management sessions time out?",
        kind=ControlKind.THRESHOLD,
        severity=Severity.MEDIUM,
        category="management",
        mappings=(
            _nist("AC-11", "Device Lock"),
            _nist("AC-12", "Session Termination"),
            _nist("SC-10", "Network Disconnect"),
            _cis_ios("1.2.7", "Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0'"),
            _cis_ios("1.2.8", "Set 'exec-timeout' to less than or equal to 10 minutes 'line vty'"),
            _cis_fortigate("2.4.4", "Ensure Admin idle timeout time is configured"),
            _stig("SRG-APP-000190-NDM-000267",
                "The network device must be configured to terminate a management session after an "
                "organization-defined period of inactivity"),
            _iso("A.5.15", "Access control"),
            _iso("A.8.5", "Secure authentication"),
        ),
        remediation_keys=("MGMT-006",),
        needs=(P.IDLE_TIMEOUT,),
    ),
    Control(
        control_id="MGMT-007",
        title="SSH Version 1 or Weak SSH Configuration",
        question="Is SSH restricted to protocol version 2?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.HIGH,
        category="management",
        mappings=(
            _nist("SC-8", "Transmission Confidentiality and Integrity"),
            _nist("AC-17(2)", "Protection of Confidentiality and Integrity Using Encryption"),
            _cis_ios("2.1.1.2", "Set version 2 for 'ip ssh version'"),
            _stig("SRG-APP-000412-NDM-000331",
                "The network device must be configured to implement cryptographic mechanisms to protect the "
                "confidentiality of remote maintenance sessions"),
            _stig("SRG-APP-000142-NDM-000245",
                "The network device must be configured to prohibit the use of all unnecessary and nonsecure "
                "functions, ports, protocols, and services"),
            _iso("A.8.24", "Use of cryptography"),
            _iso("A.8.20", "Networks security"),
        ),
        remediation_keys=("MGMT-007",),
        needs=(P.SSH_VERSION,),
    ),
    Control(
        control_id="MGMT-008",
        title="AAA (Authentication, Authorization, Accounting) Not Configured",
        question="Is AAA enabled for administrative access?",
        kind=ControlKind.REQUIREMENT,
        severity=Severity.HIGH,
        category="management",
        mappings=(
            _nist("IA-2", "Identification and Authentication (Organizational Users)"),
            _nist("AC-2", "Account Management"),
            _cis_ios("1.1.1", "Enable 'aaa new-model'"),
            _stig("SRG-APP-000516-NDM-000336",
                "The network device must be configured to use an authentication server to authenticate users "
                "prior to granting administrative access"),
            _iso("A.5.16", "Identity management"),
            _iso("A.8.5", "Secure authentication"),
            _iso("A.8.2", "Privileged access rights"),
        ),
        remediation_keys=("MGMT-008",),
        needs=(P.CENTRAL_AAA,),
    ),
    Control(
        control_id="MGMT-009",
        title="Missing Login Banner",
        question="Is a legal warning banner shown before login?",
        kind=ControlKind.REQUIREMENT,
        severity=Severity.LOW,
        category="management",
        mappings=(
            _nist("AC-8", "System Use Notification"),
            # 1.3.3 (banner motd) is not mapped: the banner fact does not tell a motd banner from a login banner
            _cis_ios("1.3.2", "Set the 'banner-text' for 'banner login'"),
            _cis_fortigate("2.1.1", "Ensure 'Pre-Login Banner' is set"),
            _stig("SRG-APP-000068-NDM-000215",
                "The network device must be configured to display the Standard Mandatory DoD Notice and "
                "Consent Banner before granting access"),
            _iso("A.5.10", "Acceptable use of information and other associated assets"),
        ),
        remediation_keys=("MGMT-009",),
        needs=(P.LOGIN_BANNER,),
    ),
    Control(
        control_id="MGMT-010",
        title="Management Reachable from an Untrusted Interface",
        question="Are management services kept off external (internet-facing) interfaces and zones?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.CRITICAL,
        category="management",
        mappings=(
            _nist("SC-7", "Boundary Protection"),
            _nist("AC-17(1)", "Monitoring and Control"),
            _nist("CM-7", "Least Functionality"),
            _cis_fortigate("1.3", "Disable all management related services on WAN port"),
            _stig("SRG-APP-000142-NDM-000245",
                "The network device must be configured to prohibit the use of all unnecessary and nonsecure "
                "functions, ports, protocols, and services"),
            _iso("A.8.20", "Networks security"),
            _iso("A.8.22", "Segregation of networks"),
        ),
        remediation_keys=("MGMT-010",),
        needs=(P.MGMT_EXPOSED,),
        # IOS binds no management service to an interface (VTY access is MGMT-003's question)
        optional_feature="management services bound to interfaces",
    ),
    Control(
        control_id="MGMT-011",
        title="SNMPv1/v2c in Use",
        question="Is SNMP limited to version 3, with no community-based (v1/v2c) access?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.HIGH,
        category="management",
        mappings=(
            _nist("SC-8", "Transmission Confidentiality and Integrity"),
            _nist("IA-2", "Identification and Authentication (Organizational Users)"),
            _cis_fortigate("2.3.1", "Ensure only SNMPv3 is enabled"),
            _stig("SRG-APP-000142-NDM-000245",
                "The network device must be configured to prohibit the use of all unnecessary and nonsecure "
                "functions, ports, protocols, and services"),
            _iso("A.8.21", "Security of network services"),
            _iso("A.8.24", "Use of cryptography"),
        ),
        remediation_keys=("MGMT-011",),
        # a community exists only in SNMPv1/v2c: the same facts MGMT-004 reads answer this question
        needs=(P.SNMP_COMMUNITY,),
    ),
    Control(
        control_id="AUTH-001",
        title="No Login Brute-Force Protection",
        question="Does the device limit failed login attempts (10 or fewer before a lockout or disconnect)?",
        kind=ControlKind.THRESHOLD,
        severity=Severity.HIGH,
        category="authentication",
        mappings=(
            _nist("AC-7", "Unsuccessful Logon Attempts"),
            _nist("IA-2", "Identification and Authentication (Organizational Users)"),
            _iso("A.8.5", "Secure authentication"),
        ),
        remediation_keys=("AUTH-001",),
        needs=(P.LOGIN_MAX_ATTEMPTS,),
    ),
    Control(
        control_id="AUTH-002",
        title="Weak Password Policy",
        question="Does the device enforce a minimum password length of at least 8 characters?",
        kind=ControlKind.THRESHOLD,
        severity=Severity.MEDIUM,
        category="authentication",
        mappings=(
            _nist("IA-5(1)", "Password-based Authentication"),
            _nist("IA-5", "Authenticator Management"),
            _iso("A.5.17", "Authentication information"),
        ),
        remediation_keys=("AUTH-002",),
        needs=(P.PASSWORD_MIN_LENGTH,),
    ),
    Control(
        control_id="AUTH-003",
        title="Default Administrator Account in Use",
        question="Are local administrative accounts renamed from vendor defaults such as 'admin' or 'root'?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.MEDIUM,
        category="authentication",
        mappings=(
            _nist("AC-2", "Account Management"),
            _nist("IA-2", "Identification and Authentication (Organizational Users)"),
            _iso("A.5.16", "Identity management"),
            _iso("A.8.2", "Privileged access rights"),
        ),
        remediation_keys=("AUTH-003",),
        needs=(P.ADMIN_ACCOUNT,),
    ),
    Control(
        control_id="BOUNDARY-001",
        title="Overly Permissive Firewall/ACL Rules",
        question="Does every ACL and firewall policy avoid permitting all traffic from any source to any destination?",
        kind=ControlKind.RELATIONAL,
        severity=Severity.CRITICAL,
        category="boundary",
        mappings=(
            _nist("AC-4", "Information Flow Enforcement"),
            _nist("SC-7", "Boundary Protection"),
            _nist("SC-7(5)", "Deny by Default -Allow by Exception"),
            _cis_fortigate("3.2", 'Ensure that policies do not use "ALL" as Service'),
            _iso("A.8.20", "Networks security"),
            _iso("A.8.22", "Segregation of networks"),
            _iso("A.8.3", "Information access restriction"),
        ),
        remediation_keys=("BOUNDARY-001",),
        needs=(P.PERMIT_ANY,),
    ),
    Control(
        control_id="BOUNDARY-002",
        title="IP Source Routing Enabled",
        question="Is IP source routing disabled?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.MEDIUM,
        category="boundary",
        mappings=(
            _nist("SC-7", "Boundary Protection"),
            _nist("CM-7", "Least Functionality"),
            _cis_ios("3.1.1", "Set 'no ip source-route'", version=CIS_IOS_XE_210_L1),
            _stig("SRG-APP-000142-NDM-000245",
                "The network device must be configured to prohibit the use of all unnecessary and nonsecure "
                "functions, ports, protocols, and services"),
            _iso("A.8.20", "Networks security"),
            _iso("A.8.9", "Configuration management"),
        ),
        remediation_keys=("BOUNDARY-002",),
        needs=(P.SOURCE_ROUTING,),
    ),
    Control(
        control_id="BOUNDARY-003",
        title="Discovery Protocol (CDP/LLDP) Enabled on External Interface",
        question="Are discovery protocols disabled on external interfaces?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.MEDIUM,
        category="boundary",
        mappings=(
            _nist("CM-7", "Least Functionality"),
            _cis_ios("2.1.2", "Set 'no cdp run'"),
            _stig("SRG-APP-000142-NDM-000245",
                "The network device must be configured to prohibit the use of all unnecessary and nonsecure "
                "functions, ports, protocols, and services"),
            _iso("A.8.20", "Networks security"),
            _iso("A.8.9", "Configuration management"),
        ),
        remediation_keys=("BOUNDARY-003",),
        needs=(P.DISCOVERY_PROTOCOL,),
    ),
    Control(
        control_id="BOUNDARY-004",
        title="Router Interface Hardening (Redirects, Proxy-ARP, Directed Broadcast)",
        question="Do routed interfaces refuse to send ICMP redirects, answer proxy-ARP or forward directed broadcasts?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.MEDIUM,
        category="boundary",
        mappings=(
            _nist("SC-7", "Boundary Protection"),
            _nist("CM-7", "Least Functionality"),
            _iso("A.8.20", "Networks security"),
            _iso("A.8.22", "Segregation of networks"),
        ),
        remediation_keys=("BOUNDARY-004",),
        needs=(P.ROUTER_UNSAFE_SERVICE,),
        # a FortiGate interface has no such services to turn off
        optional_feature="IOS-style routed interface services",
    ),
    Control(
        control_id="LOG-001",
        title="No Remote Syslog Server Configured",
        question="Are logs forwarded to a remote log server?",
        kind=ControlKind.REQUIREMENT,
        severity=Severity.HIGH,
        category="logging",
        mappings=(
            _nist("AU-4(1)", "Transfer to Alternate Storage"),
            _nist("AU-9(2)", "Store on Separate Physical Systems or Components"),
            _cis_fortigate("7.2.1", "Centralized Logging and Reporting", version=CIS_FORTIGATE_L2),
            _stig("SRG-APP-000515-NDM-000325",
                "The network device must be configured to offload audit records onto a different system than "
                "the system being audited"),
            _iso("A.8.15", "Logging"),
            _iso("A.8.16", "Monitoring activities"),
        ),
        remediation_keys=("LOG-001",),
        needs=(P.LOG_REMOTE_DESTINATION,),
    ),
    Control(
        control_id="LOG-002",
        title="NTP Not Configured or Unauthenticated",
        question="Is the clock synchronized from authenticated NTP servers?",
        kind=ControlKind.REQUIREMENT,
        severity=Severity.MEDIUM,
        category="logging",
        mappings=(
            _nist("AU-8", "Time Stamps"),
            _nist("SC-45", "System Time Synchronization"),
            _nist("SC-45(1)", "Synchronization with Authoritative Time Source"),
            _cis_ios("2.3.1.4", "Set 'key' for each 'ntp server'", version=CIS_IOS_XE_L2),
            _cis_fortigate("2.1.4", "Ensure correct system time is configured through NTP"),
            _stig("SRG-APP-000373-NDM-000298",
                "The network device must be configured to synchronize internal information system clocks with "
                "the primary and secondary time sources"),
            _stig("SRG-APP-000395-NDM-000347",
                "The network device must be configured to authenticate Network Time Protocol sources"),
            _iso("A.8.17", "Clock synchronisation"),
            _iso("A.8.15", "Logging"),
        ),
        remediation_keys=("LOG-002",),
        needs=(P.NTP_SERVER, P.NTP_AUTHENTICATED),
    ),
    Control(
        control_id="LOG-003",
        title="Traffic Rules That Do Not Log",
        question="Does every firewall rule that permits traffic log what it matches?",
        kind=ControlKind.REQUIREMENT,
        severity=Severity.MEDIUM,
        category="logging",
        mappings=(
            _nist("AU-2", "Event Logging"),
            _nist("AU-12", "Audit Record Generation"),
            _iso("A.8.15", "Logging"),
            _iso("A.8.16", "Monitoring activities"),
        ),
        remediation_keys=("LOG-003",),
        needs=(P.RULE_LOGGING,),
        # a router's ACLs are not firewall policies: CIS asks nothing of ACL logging
        optional_feature="firewall policies",
    ),
    Control(
        control_id="CRYPTO-001",
        title="Weak VPN/IPsec Cryptographic Algorithms",
        question="Do VPN proposals avoid weak encryption, hashing and Diffie-Hellman groups?",
        kind=ControlKind.THRESHOLD,
        severity=Severity.HIGH,
        category="cryptography",
        mappings=(
            _nist("SC-13", "Cryptographic Protection"),
            _nist("SC-8", "Transmission Confidentiality and Integrity"),
            _stig("SRG-APP-000412-NDM-000331",
                "The network device must be configured to implement cryptographic mechanisms to protect the "
                "confidentiality of remote maintenance sessions"),
            _iso("A.8.24", "Use of cryptography"),
            _iso("A.8.20", "Networks security"),
        ),
        remediation_keys=("CRYPTO-001",),
        needs=(P.IPSEC_PROPOSAL,),
        optional_feature="a VPN or IPsec tunnel",
    ),
    Control(
        control_id="CRYPTO-002",
        title="Weak Management Cryptography (SSH/HTTPS)",
        question="Do SSH and HTTPS management avoid weak ciphers, MACs and key exchange (DES, 3DES, RC4, CBC, MD5, DH group 1)?",
        kind=ControlKind.PROHIBITION,
        severity=Severity.HIGH,
        category="cryptography",
        mappings=(
            _nist("SC-13", "Cryptographic Protection"),
            _nist("SC-8", "Transmission Confidentiality and Integrity"),
            _stig("SRG-APP-000412-NDM-000331",
                "The network device must be configured to implement cryptographic mechanisms to protect the "
                "confidentiality of remote maintenance sessions"),
            _iso("A.8.24", "Use of cryptography"),
        ),
        remediation_keys=("CRYPTO-002",),
        needs=(P.MGMT_WEAK_CRYPTO,),
    ),
)

CONTROLS: dict[str, Control] = {control.control_id: control for control in _CONTROLS}
