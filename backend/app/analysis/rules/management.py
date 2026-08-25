"""
Management plane security rules.

These check how the device is administered: SSH/Telnet settings,
SNMP configuration, password strength, session timeouts, etc.
"""

from __future__ import annotations
from app.models.normalized import NormalizedConfig, Vendor
from app.models.findings import Finding, Severity, ComplianceMapping
from app.analysis.rules.base import BaseRule


DEFAULT_SNMP_COMMUNITIES = {"public", "private", "community", "snmp", "default"}


class TelnetEnabledRule(BaseRule):
    rule_id = "MGMT-001"
    title = "Insecure Management Protocol (Telnet) Enabled"
    category = "management"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        if config.device.vendor == Vendor.CISCO_IOS:
            for vty in config.management.vty_lines:
                if "telnet" in vty.transport_input or "all" in vty.transport_input:
                    findings.append(self._make_finding(
                        config,
                        Severity.CRITICAL,
                        "Telnet is enabled for remote management. Telnet transmits "
                        "credentials and commands in cleartext, making them visible "
                        "to anyone who can sniff the network.",
                        self._get_evidence(config, vty.source_lines),
                        vty.source_lines,
                        "An attacker on the network path can capture admin credentials "
                        "by passively eavesdropping on Telnet sessions.",
                        "Disable Telnet and use SSH only: set 'transport input ssh' on all VTY lines.",
                        [
                            ComplianceMapping("CIS", "1.1.1", "Set transport input ssh for line vty"),
                            ComplianceMapping("NIST_800_53", "AC-17(2)", "Protection of Confidentiality/Integrity Using Encryption"),
                            ComplianceMapping("NIST_800_53", "SC-8", "Transmission Confidentiality and Integrity"),
                        ],
                    ))
                    break  # One finding is enough

        elif config.device.vendor == Vendor.FORTINET:
            for iface in config.interfaces:
                if "telnet" in iface.allowed_services:
                    findings.append(self._make_finding(
                        config,
                        Severity.CRITICAL,
                        f"Telnet is allowed on interface '{iface.name}'. Telnet transmits "
                        "all traffic including credentials in cleartext.",
                        self._get_evidence(config, iface.source_lines),
                        iface.source_lines,
                        "Management credentials can be intercepted by network eavesdropping.",
                        f"Remove 'telnet' from allowaccess on interface '{iface.name}'.",
                        [
                            ComplianceMapping("CIS", "1.1.1", "Disable insecure management protocols"),
                            ComplianceMapping("NIST_800_53", "AC-17(2)", "Protection of Confidentiality/Integrity Using Encryption"),
                        ],
                    ))

        return findings


class HttpServerEnabledRule(BaseRule):
    rule_id = "MGMT-002"
    title = "Insecure HTTP Management Enabled"
    category = "management"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        if config.device.vendor == Vendor.CISCO_IOS:
            if config.management.http_enabled:
                findings.append(self._make_finding(
                    config,
                    Severity.HIGH,
                    "The HTTP management server is enabled. HTTP transmits web management "
                    "traffic in cleartext, including session cookies and credentials.",
                    self._get_evidence(config, config.management.source_lines),
                    config.management.source_lines,
                    "Web management sessions can be hijacked via cookie theft or credential interception.",
                    "Disable HTTP and enable HTTPS: 'no ip http server' and 'ip http secure-server'.",
                    [
                        ComplianceMapping("CIS", "2.1.3", "Unset ip http server"),
                        ComplianceMapping("NIST_800_53", "SC-8", "Transmission Confidentiality and Integrity"),
                    ],
                ))

        elif config.device.vendor == Vendor.FORTINET:
            for iface in config.interfaces:
                if "http" in iface.allowed_services and iface.is_wan:
                    findings.append(self._make_finding(
                        config,
                        Severity.HIGH,
                        f"HTTP management is allowed on WAN interface '{iface.name}'. "
                        "This exposes the admin panel over cleartext to external networks.",
                        self._get_evidence(config, iface.source_lines),
                        iface.source_lines,
                        "Admin panel exposed to the internet over an unencrypted protocol.",
                        f"Remove 'http' from allowaccess on '{iface.name}'. Use HTTPS only.",
                        [
                            ComplianceMapping("CIS", "1.1.1", "Disable insecure management protocols"),
                            ComplianceMapping("NIST_800_53", "SC-8", "Transmission Confidentiality and Integrity"),
                        ],
                    ))

        return findings


class UnrestrictedManagementAccessRule(BaseRule):
    rule_id = "MGMT-003"
    title = "Unrestricted Management Access"
    category = "management"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        if config.device.vendor == Vendor.CISCO_IOS:
            for vty in config.management.vty_lines:
                if not vty.access_class:
                    findings.append(self._make_finding(
                        config,
                        Severity.CRITICAL,
                        f"VTY lines ({vty.line_range}) have no access-class restricting "
                        "which IP addresses can connect. Any host on the network can "
                        "attempt to log in.",
                        self._get_evidence(config, vty.source_lines),
                        vty.source_lines,
                        "The management interface is exposed to brute-force attacks from "
                        "any network, including the internet if the device is routable.",
                        "Apply an access-class with a management ACL: 'access-class MGMT_ACL in'.",
                        [
                            ComplianceMapping("CIS", "1.1.4", "Set access-class for line vty"),
                            ComplianceMapping("NIST_800_53", "AC-3", "Access Enforcement"),
                            ComplianceMapping("NIST_800_53", "AC-17(1)", "Monitoring/Control"),
                        ],
                    ))
                    break

        elif config.device.vendor == Vendor.FORTINET:
            # Check if admin services are allowed on WAN interfaces
            for iface in config.interfaces:
                if not iface.is_wan:
                    continue
                mgmt_services = {"ssh", "https", "http", "telnet"}
                exposed = mgmt_services.intersection(iface.allowed_services)
                if exposed:
                    findings.append(self._make_finding(
                        config,
                        Severity.CRITICAL,
                        f"Management services ({', '.join(sorted(exposed))}) are accessible "
                        f"on WAN interface '{iface.name}'. This exposes the admin panel "
                        "to the internet.",
                        self._get_evidence(config, iface.source_lines),
                        iface.source_lines,
                        "The management interface is reachable from untrusted networks, "
                        "making it a target for brute-force and exploit attacks.",
                        f"Remove management services from WAN interface '{iface.name}'. "
                        "Only allow management from internal/management networks.",
                        [
                            ComplianceMapping("CIS", "1.2.2", "Restrict admin access to trusted hosts"),
                            ComplianceMapping("NIST_800_53", "AC-17", "Remote Access"),
                            ComplianceMapping("NIST_800_53", "SC-7", "Boundary Protection"),
                        ],
                    ))

        return findings


class WeakSnmpRule(BaseRule):
    rule_id = "MGMT-004"
    title = "Weak or Default SNMP Community Strings"
    category = "management"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        for community in config.snmp.communities:
            is_default = community.name.lower() in DEFAULT_SNMP_COMMUNITIES
            no_acl = community.acl is None

            if is_default or (community.permission == "RW" and no_acl):
                severity = Severity.CRITICAL if community.permission == "RW" else Severity.HIGH

                problem = []
                if is_default:
                    problem.append(f"uses the well-known default string '{community.name}'")
                if community.permission == "RW" and no_acl:
                    problem.append("grants read-write access without an ACL restriction")

                findings.append(self._make_finding(
                    config,
                    severity,
                    f"SNMP community '{community.name}' ({community.permission}) "
                    f"{' and '.join(problem)}.",
                    self._get_evidence(config, community.source_lines),
                    community.source_lines,
                    "Default SNMP community strings are the first thing attackers try. "
                    "Read-write access allows full device reconfiguration via SNMP.",
                    "Remove default communities. Use SNMPv3 with authentication and encryption, "
                    "or at minimum use non-default community strings with ACL restrictions.",
                    [
                        ComplianceMapping("CIS", "1.3.1", "Set SNMP community strings"),
                        ComplianceMapping("NIST_800_53", "IA-5", "Authenticator Management"),
                    ],
                ))

        return findings


class WeakPasswordsRule(BaseRule):
    """Cisco-specific: checks for plaintext or easily reversible passwords."""
    rule_id = "MGMT-005"
    title = "Plaintext or Weakly Encrypted Passwords"
    category = "management"

    WEAK_TYPES = {"plaintext", "type7", "type0"}

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        if config.device.vendor != Vendor.CISCO_IOS:
            return []

        findings = []

        # Check enable password
        if config.authentication.enable_password_type in self.WEAK_TYPES:
            findings.append(self._make_finding(
                config,
                Severity.CRITICAL,
                f"The enable password uses {config.authentication.enable_password_type} "
                "encoding, which is trivially reversible. Anyone with access to the "
                "config file can recover the password instantly.",
                self._get_evidence(config, config.authentication.source_lines),
                config.authentication.source_lines,
                "Enable password protects privileged EXEC mode. If it's reversible, "
                "any config backup leak gives full device control.",
                "Use 'enable algorithm-type scrypt secret' instead of 'enable password'.",
                [
                    ComplianceMapping("CIS", "1.2.1", "Set enable secret"),
                    ComplianceMapping("NIST_800_53", "IA-5(1)", "Password-Based Authentication"),
                ],
            ))

        # Check user passwords
        for user in config.authentication.local_users:
            if user.password_type in self.WEAK_TYPES:
                findings.append(self._make_finding(
                    config,
                    Severity.CRITICAL,
                    f"User '{user.username}' has a {user.password_type} password. "
                    "Type 7 passwords can be decoded in milliseconds with freely "
                    "available tools. Plaintext passwords are visible directly.",
                    self._get_evidence(config, user.source_lines),
                    user.source_lines,
                    "Compromised user credentials allow unauthorized device access.",
                    f"Change user '{user.username}' to use 'username {user.username} "
                    "algorithm-type scrypt secret <password>'.",
                    [
                        ComplianceMapping("CIS", "1.2.3", "Set password for local users"),
                        ComplianceMapping("NIST_800_53", "IA-5(1)", "Password-Based Authentication"),
                    ],
                ))

        # Check if password encryption service is missing
        if not config.services.password_encryption:
            findings.append(self._make_finding(
                config,
                Severity.HIGH,
                "The 'service password-encryption' command is not configured. "
                "Some passwords in the config may be stored in cleartext.",
                self._get_evidence(config, config.services.source_lines),
                config.services.source_lines,
                "Cleartext passwords are visible to anyone viewing the config.",
                "Enable 'service password-encryption'. Note: this only provides "
                "Type 7 encoding which is weak, but it's better than plaintext.",
                [
                    ComplianceMapping("CIS", "1.1.1", "Enable service password-encryption"),
                    ComplianceMapping("NIST_800_53", "IA-5", "Authenticator Management"),
                ],
            ))

        return findings


class NoExecTimeoutRule(BaseRule):
    rule_id = "MGMT-006"
    title = "Missing or Disabled Session Timeout"
    category = "management"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        if config.device.vendor == Vendor.CISCO_IOS:
            for vty in config.management.vty_lines:
                if not vty.has_timeout:
                    findings.append(self._make_finding(
                        config,
                        Severity.MEDIUM,
                        f"VTY lines ({vty.line_range}) have no exec-timeout or timeout "
                        "is set to 0 (disabled). Idle sessions stay open indefinitely.",
                        self._get_evidence(config, vty.source_lines),
                        vty.source_lines,
                        "An unattended terminal left logged in can be used by anyone "
                        "with physical or remote access to the admin workstation.",
                        "Set a reasonable timeout: 'exec-timeout 5 0' (5 minutes).",
                        [
                            ComplianceMapping("CIS", "2.1.5", "Set exec-timeout on VTY"),
                            ComplianceMapping("NIST_800_53", "AC-11", "Device Lock"),
                            ComplianceMapping("NIST_800_53", "AC-12", "Session Termination"),
                        ],
                    ))
                    break

            if config.management.console and not config.management.console.has_timeout:
                findings.append(self._make_finding(
                    config,
                    Severity.MEDIUM,
                    "Console line has no exec-timeout or timeout is disabled.",
                    self._get_evidence(config, config.management.console.source_lines),
                    config.management.console.source_lines,
                    "Physical console sessions remain open indefinitely.",
                    "Set 'exec-timeout 5 0' on the console line.",
                    [
                        ComplianceMapping("CIS", "2.1.4", "Set exec-timeout on console"),
                        ComplianceMapping("NIST_800_53", "AC-12", "Session Termination"),
                    ],
                ))

        elif config.device.vendor == Vendor.FORTINET:
            timeout = config.management.admin_timeout
            # FortiGate default is 5 minutes, but anything over 15 is too high
            if timeout is not None and timeout > 15:
                findings.append(self._make_finding(
                    config,
                    Severity.MEDIUM,
                    f"Admin session timeout is set to {timeout} minutes, which is "
                    "excessively long for a management session.",
                    self._get_evidence(config, config.management.source_lines),
                    config.management.source_lines,
                    "Long session timeouts increase the risk of session hijacking "
                    "or unauthorized use of unattended admin sessions.",
                    "Set admintimeout to 5 minutes or less.",
                    [
                        ComplianceMapping("CIS", "1.2.3", "Set admin session timeout"),
                        ComplianceMapping("NIST_800_53", "AC-11", "Device Lock"),
                    ],
                ))

        return findings


class SshWeaknessRule(BaseRule):
    rule_id = "MGMT-007"
    title = "SSH Version 1 or Weak SSH Configuration"
    category = "management"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        if config.device.vendor == Vendor.CISCO_IOS:
            if config.management.ssh_version == 1:
                findings.append(self._make_finding(
                    config,
                    Severity.HIGH,
                    "SSH version 1 is configured. SSHv1 has known cryptographic "
                    "weaknesses and is vulnerable to man-in-the-middle attacks.",
                    self._get_evidence(config, config.management.source_lines),
                    config.management.source_lines,
                    "SSHv1 sessions can be intercepted and decrypted.",
                    "Set 'ip ssh version 2'.",
                    [
                        ComplianceMapping("CIS", "1.1.3", "Set SSH version 2"),
                        ComplianceMapping("NIST_800_53", "SC-8", "Transmission Confidentiality"),
                    ],
                ))

        elif config.device.vendor == Vendor.FORTINET:
            # Check for admin-ssh-v1 enable in management config
            if config.management.ssh_version == 1:
                findings.append(self._make_finding(
                    config,
                    Severity.HIGH,
                    "SSH version 1 is enabled (admin-ssh-v1 enable). SSHv1 has "
                    "known vulnerabilities and should not be used.",
                    self._get_evidence(config, config.management.source_lines),
                    config.management.source_lines,
                    "SSHv1 is cryptographically broken and can be exploited.",
                    "Disable SSHv1: 'set admin-ssh-v1 disable' in system global.",
                    [
                        ComplianceMapping("CIS", "1.2.4", "Disable SSHv1"),
                        ComplianceMapping("NIST_800_53", "SC-8", "Transmission Confidentiality"),
                    ],
                ))

        return findings


class NoAaaRule(BaseRule):
    """Cisco-specific: checks if AAA is configured."""
    rule_id = "MGMT-008"
    title = "AAA (Authentication, Authorization, Accounting) Not Configured"
    category = "management"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        if config.device.vendor != Vendor.CISCO_IOS:
            return []

        if not config.authentication.aaa_enabled:
            return [self._make_finding(
                config,
                Severity.HIGH,
                "AAA is not configured ('aaa new-model' is missing). The device "
                "uses basic line-level authentication with no centralized access "
                "control, authorization, or accounting.",
                self._get_evidence(config, config.authentication.source_lines),
                config.authentication.source_lines,
                "Without AAA, there's no per-user accountability, no centralized "
                "authentication (TACACS+/RADIUS), and no audit trail of admin actions.",
                "Enable AAA: 'aaa new-model' and configure authentication methods.",
                [
                    ComplianceMapping("CIS", "2.2.1", "Set AAA new-model"),
                    ComplianceMapping("NIST_800_53", "IA-2", "Identification and Authentication"),
                    ComplianceMapping("NIST_800_53", "AC-2", "Account Management"),
                ],
            )]

        return []


class MissingBannerRule(BaseRule):
    rule_id = "MGMT-009"
    title = "Missing Login Banner"
    category = "management"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        if config.device.vendor == Vendor.CISCO_IOS:
            if not config.banners.login_banner and not config.banners.motd_banner:
                findings.append(self._make_finding(
                    config,
                    Severity.LOW,
                    "No login or MOTD banner is configured. A warning banner is "
                    "a legal requirement in many jurisdictions for prosecuting "
                    "unauthorized access.",
                    self._get_evidence(config, config.banners.source_lines),
                    config.banners.source_lines,
                    "Without a banner, unauthorized access may be harder to prosecute.",
                    "Configure a login banner with a legal warning message.",
                    [
                        ComplianceMapping("CIS", "1.1.6", "Set login banner"),
                        ComplianceMapping("NIST_800_53", "AC-8", "System Use Notification"),
                    ],
                ))

        elif config.device.vendor == Vendor.FORTINET:
            if config.banners.pre_login_banner_enabled is False:
                findings.append(self._make_finding(
                    config,
                    Severity.LOW,
                    "Pre-login banner is disabled. A warning banner is recommended "
                    "for legal and compliance purposes.",
                    self._get_evidence(config, config.banners.source_lines),
                    config.banners.source_lines,
                    "Without a banner, unauthorized access may be harder to prosecute.",
                    "Enable pre-login banner: 'set pre-login-banner enable' in system global.",
                    [
                        ComplianceMapping("CIS", "1.2.5", "Enable pre-login banner"),
                        ComplianceMapping("NIST_800_53", "AC-8", "System Use Notification"),
                    ],
                ))

        return findings


# All management rules in one list for the engine to use
MANAGEMENT_RULES: list[BaseRule] = [
    TelnetEnabledRule(),
    HttpServerEnabledRule(),
    UnrestrictedManagementAccessRule(),
    WeakSnmpRule(),
    WeakPasswordsRule(),
    NoExecTimeoutRule(),
    SshWeaknessRule(),
    NoAaaRule(),
    MissingBannerRule(),
]
