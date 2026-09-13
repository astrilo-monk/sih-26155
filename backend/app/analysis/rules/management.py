"""
Management plane controls.

How the device is administered: SSH/Telnet, HTTP, management access
restrictions, SNMP, password storage, session timeouts, AAA and banners.
"""

from __future__ import annotations

from app.analysis.rules.base import BaseRule
from app.models.findings import Severity
from app.models.normalized import NormalizedConfig, Vendor
from app.models.results import ControlResult

DEFAULT_SNMP_COMMUNITIES = {"public", "private", "community", "snmp", "default"}


class TelnetEnabledRule(BaseRule):
    rule_id = "MGMT-001"
    vendor_gated = True

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []

        if config.device.vendor == Vendor.CISCO_IOS:
            for vty in config.management.vty_lines:
                if "telnet" in vty.transport_input or "all" in vty.transport_input:
                    results.append(self._fail(
                        config,
                        Severity.CRITICAL,
                        "Telnet is enabled for remote management. Telnet transmits "
                        "credentials and commands in cleartext, making them visible "
                        "to anyone who can sniff the network.",
                        vty.source_lines,
                        "An attacker on the network path can capture admin credentials "
                        "by passively eavesdropping on Telnet sessions.",
                        "Disable Telnet and use SSH only: set 'transport input ssh' on all VTY lines.",
                        scope=f"line vty {vty.line_range}",
                    ))
                    break  # One finding is enough

        elif config.device.vendor == Vendor.FORTINET:
            for iface in config.interfaces:
                if "telnet" in iface.allowed_services:
                    results.append(self._fail(
                        config,
                        Severity.CRITICAL,
                        f"Telnet is allowed on interface '{iface.name}'. Telnet transmits "
                        "all traffic including credentials in cleartext.",
                        iface.source_lines,
                        "Management credentials can be intercepted by network eavesdropping.",
                        f"Remove 'telnet' from allowaccess on interface '{iface.name}'.",
                        scope=f"interface {iface.name}",
                    ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        if config.device.vendor == Vendor.CISCO_IOS:
            vtys = config.management.vty_lines
            if not vtys:
                return self._not_configured(config, "No VTY lines are configured")
            implicit = [vty for vty in vtys if not vty.transport_input]
            if implicit:
                return self._unknown(
                    config,
                    f"VTY {implicit[0].line_range} has no 'transport input'; the platform default "
                    "decides (vendor defaults are evaluated in Phase 4)",
                    self._lines(*implicit),
                )
            return self._pass(config, "Telnet is not allowed on any VTY line", self._lines(*vtys))

        managed = [iface for iface in config.interfaces if iface.allowed_services]
        if not managed:
            return self._not_configured(config, "No interface allows management access")
        return self._pass(config, "No interface allows Telnet", self._lines(*managed))


class HttpServerEnabledRule(BaseRule):
    rule_id = "MGMT-002"
    vendor_gated = True

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []

        if config.device.vendor == Vendor.CISCO_IOS:
            if config.management.http_enabled:
                results.append(self._fail(
                    config,
                    Severity.HIGH,
                    "The HTTP management server is enabled. HTTP transmits web management "
                    "traffic in cleartext, including session cookies and credentials.",
                    config.management.source_lines,
                    "Web management sessions can be hijacked via cookie theft or credential interception.",
                    "Disable HTTP and enable HTTPS: 'no ip http server' and 'ip http secure-server'.",
                ))

        elif config.device.vendor == Vendor.FORTINET:
            for iface in config.interfaces:
                if "http" in iface.allowed_services and iface.is_wan:
                    results.append(self._fail(
                        config,
                        Severity.HIGH,
                        f"HTTP management is allowed on WAN interface '{iface.name}'. "
                        "This exposes the admin panel over cleartext to external networks.",
                        iface.source_lines,
                        "Admin panel exposed to the internet over an unencrypted protocol.",
                        f"Remove 'http' from allowaccess on '{iface.name}'. Use HTTPS only.",
                        scope=f"interface {iface.name}",
                    ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        if config.device.vendor == Vendor.CISCO_IOS:
            disabled = self._lines_matching(config, config.management.source_lines, r"^\s*no ip http server\s*$")
            if disabled:
                return self._pass(config, "The HTTP server is disabled", disabled)
            return self._not_configured(
                config,
                "'ip http server' is not stated; the platform default applies "
                "(vendor defaults are evaluated in Phase 4)",
            )

        wan = [iface for iface in config.interfaces if iface.is_wan]
        if not wan:
            return self._unknown(config, "No interface is identified as WAN")
        return self._pass(config, "HTTP management is not allowed on any WAN interface", self._lines(*wan))


class UnrestrictedManagementAccessRule(BaseRule):
    rule_id = "MGMT-003"
    vendor_gated = True

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []

        if config.device.vendor == Vendor.CISCO_IOS:
            for vty in config.management.vty_lines:
                if not vty.access_class:
                    results.append(self._fail(
                        config,
                        Severity.CRITICAL,
                        f"VTY lines ({vty.line_range}) have no access-class restricting "
                        "which IP addresses can connect. Any host on the network can "
                        "attempt to log in.",
                        vty.source_lines,
                        "The management interface is exposed to brute-force attacks from "
                        "any network, including the internet if the device is routable.",
                        "Apply an access-class with a management ACL: 'access-class MGMT_ACL in'.",
                        scope=f"line vty {vty.line_range}",
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
                    results.append(self._fail(
                        config,
                        Severity.CRITICAL,
                        f"Management services ({', '.join(sorted(exposed))}) are accessible "
                        f"on WAN interface '{iface.name}'. This exposes the admin panel "
                        "to the internet.",
                        iface.source_lines,
                        "The management interface is reachable from untrusted networks, "
                        "making it a target for brute-force and exploit attacks.",
                        f"Remove management services from WAN interface '{iface.name}'. "
                        "Only allow management from internal/management networks.",
                        scope=f"interface {iface.name}",
                    ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        if config.device.vendor == Vendor.CISCO_IOS:
            vtys = config.management.vty_lines
            if not vtys:
                return self._missing(config, "No VTY lines are configured")
            return self._pass(config, "Every VTY line has an access-class", self._lines(*vtys))

        wan = [iface for iface in config.interfaces if iface.is_wan]
        if not wan:
            return self._unknown(config, "No interface is identified as WAN")
        return self._pass(config, "No management service is allowed on a WAN interface", self._lines(*wan))


class WeakSnmpRule(BaseRule):
    rule_id = "MGMT-004"

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []

        for index, community in enumerate(config.snmp.communities, 1):
            is_default = community.name.lower() in DEFAULT_SNMP_COMMUNITIES
            no_acl = community.acl is None

            if is_default or (community.permission == "RW" and no_acl):
                severity = Severity.CRITICAL if community.permission == "RW" else Severity.HIGH

                problem = []
                if is_default:
                    problem.append(f"uses the well-known default string '{community.name}'")
                if community.permission == "RW" and no_acl:
                    problem.append("grants read-write access without an ACL restriction")

                results.append(self._fail(
                    config,
                    severity,
                    f"SNMP community '{community.name}' ({community.permission}) "
                    f"{' and '.join(problem)}.",
                    community.source_lines,
                    "Default SNMP community strings are the first thing attackers try. "
                    "Read-write access allows full device reconfiguration via SNMP.",
                    "Remove default communities. Use SNMPv3 with authentication and encryption, "
                    "or at minimum use non-default community strings with ACL restrictions.",
                    # The community string is a secret: identify it by position only
                    scope=f"snmp community #{index}",
                ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        communities = config.snmp.communities
        if not communities:
            return self._not_configured(config, "No SNMP community is configured")
        return self._pass(
            config,
            "No SNMP community uses a default string or grants read-write access without an ACL",
            self._lines(*communities),
        )


class WeakPasswordsRule(BaseRule):
    """Cisco-specific: checks for plaintext or easily reversible passwords."""
    rule_id = "MGMT-005"
    vendor_gated = True
    evaluated_vendors = (Vendor.CISCO_IOS,)

    WEAK_TYPES = {"plaintext", "type7", "type0"}

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        if config.device.vendor != Vendor.CISCO_IOS:
            return []

        results = []

        # Check enable password
        if config.authentication.enable_password_type in self.WEAK_TYPES:
            results.append(self._fail(
                config,
                Severity.CRITICAL,
                f"The enable password uses {config.authentication.enable_password_type} "
                "encoding, which is trivially reversible. Anyone with access to the "
                "config file can recover the password instantly.",
                config.authentication.source_lines,
                "Enable password protects privileged EXEC mode. If it's reversible, "
                "any config backup leak gives full device control.",
                "Use 'enable algorithm-type scrypt secret' instead of 'enable password'.",
                scope="enable password",
            ))

        # Check user passwords
        for user in config.authentication.local_users:
            if user.password_type in self.WEAK_TYPES:
                results.append(self._fail(
                    config,
                    Severity.CRITICAL,
                    f"User '{user.username}' has a {user.password_type} password. "
                    "Type 7 passwords can be decoded in milliseconds with freely "
                    "available tools. Plaintext passwords are visible directly.",
                    user.source_lines,
                    "Compromised user credentials allow unauthorized device access.",
                    f"Change user '{user.username}' to use 'username {user.username} "
                    "algorithm-type scrypt secret <password>'.",
                    scope=f"user {user.username}",
                ))

        # Check if password encryption service is missing
        if not config.services.password_encryption:
            results.append(self._fail(
                config,
                Severity.HIGH,
                "The 'service password-encryption' command is not configured. "
                "Some passwords in the config may be stored in cleartext.",
                config.services.source_lines,
                "Cleartext passwords are visible to anyone viewing the config.",
                "Enable 'service password-encryption'. Note: this only provides "
                "Type 7 encoding which is weak, but it's better than plaintext.",
                scope="service password-encryption",
            ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        return self._pass(
            config,
            "'service password-encryption' is set and no plaintext or Type 7 password was found",
            self._lines_matching(
                config,
                config.authentication.source_lines + config.services.source_lines + self._lines(*config.authentication.local_users),
                r"password|secret",
            ),
        )


class NoExecTimeoutRule(BaseRule):
    rule_id = "MGMT-006"
    vendor_gated = True

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []

        if config.device.vendor == Vendor.CISCO_IOS:
            for vty in config.management.vty_lines:
                if not vty.has_timeout:
                    results.append(self._fail(
                        config,
                        Severity.MEDIUM,
                        f"VTY lines ({vty.line_range}) have no exec-timeout or timeout "
                        "is set to 0 (disabled). Idle sessions stay open indefinitely.",
                        vty.source_lines,
                        "An unattended terminal left logged in can be used by anyone "
                        "with physical or remote access to the admin workstation.",
                        "Set a reasonable timeout: 'exec-timeout 5 0' (5 minutes).",
                        scope=f"line vty {vty.line_range}",
                    ))
                    break

            if config.management.console and not config.management.console.has_timeout:
                results.append(self._fail(
                    config,
                    Severity.MEDIUM,
                    "Console line has no exec-timeout or timeout is disabled.",
                    config.management.console.source_lines,
                    "Physical console sessions remain open indefinitely.",
                    "Set 'exec-timeout 5 0' on the console line.",
                    scope="line con 0",
                ))

        elif config.device.vendor == Vendor.FORTINET:
            timeout = config.management.admin_timeout
            # FortiGate default is 5 minutes, but anything over 15 is too high
            if timeout is not None and timeout > 15:
                results.append(self._fail(
                    config,
                    Severity.MEDIUM,
                    f"Admin session timeout is set to {timeout} minutes, which is "
                    "excessively long for a management session.",
                    config.management.source_lines,
                    "Long session timeouts increase the risk of session hijacking "
                    "or unauthorized use of unattended admin sessions.",
                    "Set admintimeout to 5 minutes or less.",
                ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        if config.device.vendor == Vendor.CISCO_IOS:
            lines = list(config.management.vty_lines)
            if config.management.console:
                lines.append(config.management.console)
            if not lines:
                return self._not_configured(config, "No VTY or console line is configured")
            return self._pass(config, "Every VTY and console line has an exec-timeout", self._lines(*lines))

        timeout = config.management.admin_timeout
        if timeout is None:
            return self._not_configured(
                config,
                "'admintimeout' is not set; the FortiOS default applies (vendor defaults are evaluated in Phase 4)",
            )
        return self._pass(
            config,
            f"The admin idle timeout is {timeout} minutes",
            self._lines_matching(config, config.management.source_lines, r"admintimeout"),
        )


class SshWeaknessRule(BaseRule):
    rule_id = "MGMT-007"
    vendor_gated = True

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []

        if config.device.vendor == Vendor.CISCO_IOS:
            if config.management.ssh_version == 1:
                results.append(self._fail(
                    config,
                    Severity.HIGH,
                    "SSH version 1 is configured. SSHv1 has known cryptographic "
                    "weaknesses and is vulnerable to man-in-the-middle attacks.",
                    config.management.source_lines,
                    "SSHv1 sessions can be intercepted and decrypted.",
                    "Set 'ip ssh version 2'.",
                ))

        elif config.device.vendor == Vendor.FORTINET:
            # Check for admin-ssh-v1 enable in management config
            if config.management.ssh_version == 1:
                results.append(self._fail(
                    config,
                    Severity.HIGH,
                    "SSH version 1 is enabled (admin-ssh-v1 enable). SSHv1 has "
                    "known vulnerabilities and should not be used.",
                    config.management.source_lines,
                    "SSHv1 is cryptographically broken and can be exploited.",
                    "Disable SSHv1: 'set admin-ssh-v1 disable' in system global.",
                ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        cisco = config.device.vendor == Vendor.CISCO_IOS
        setting, pattern = ("'ip ssh version'", r"ip ssh version") if cisco else ("'admin-ssh-v1'", r"admin-ssh-v1")
        if config.management.ssh_version is None:
            return self._not_configured(
                config,
                f"{setting} is not set; the platform default applies (vendor defaults are evaluated in Phase 4)",
            )
        return self._pass(
            config,
            f"SSH version {config.management.ssh_version} only",
            self._lines_matching(config, config.management.source_lines, pattern),
        )


class NoAaaRule(BaseRule):
    """Cisco-specific: checks if AAA is configured."""
    rule_id = "MGMT-008"
    vendor_gated = True
    evaluated_vendors = (Vendor.CISCO_IOS,)

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        if config.device.vendor != Vendor.CISCO_IOS:
            return []

        if not config.authentication.aaa_enabled:
            return [self._fail(
                config,
                Severity.HIGH,
                "AAA is not configured ('aaa new-model' is missing). The device "
                "uses basic line-level authentication with no centralized access "
                "control, authorization, or accounting.",
                config.authentication.source_lines,
                "Without AAA, there's no per-user accountability, no centralized "
                "authentication (TACACS+/RADIUS), and no audit trail of admin actions.",
                "Enable AAA: 'aaa new-model' and configure authentication methods.",
            )]

        return []

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        return self._pass(
            config,
            "AAA is enabled ('aaa new-model')",
            self._lines_matching(config, config.authentication.source_lines, r"^\s*aaa new-model"),
        )


class MissingBannerRule(BaseRule):
    rule_id = "MGMT-009"
    vendor_gated = True

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []

        if config.device.vendor == Vendor.CISCO_IOS:
            if not config.banners.login_banner and not config.banners.motd_banner:
                results.append(self._fail(
                    config,
                    Severity.LOW,
                    "No login or MOTD banner is configured. A warning banner is "
                    "a legal requirement in many jurisdictions for prosecuting "
                    "unauthorized access.",
                    config.banners.source_lines,
                    "Without a banner, unauthorized access may be harder to prosecute.",
                    "Configure a login banner with a legal warning message.",
                ))

        elif config.device.vendor == Vendor.FORTINET:
            if config.banners.pre_login_banner_enabled is False:
                results.append(self._fail(
                    config,
                    Severity.LOW,
                    "Pre-login banner is disabled. A warning banner is recommended "
                    "for legal and compliance purposes.",
                    config.banners.source_lines,
                    "Without a banner, unauthorized access may be harder to prosecute.",
                    "Enable pre-login banner: 'set pre-login-banner enable' in system global.",
                ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        if config.device.vendor == Vendor.CISCO_IOS:
            return self._pass(config, "A login or MOTD banner is configured", config.banners.source_lines)
        if config.banners.pre_login_banner_enabled is None:
            return self._not_configured(
                config,
                "'pre-login-banner' is not set; the FortiOS default applies (vendor defaults are evaluated in Phase 4)",
            )
        return self._pass(config, "The pre-login banner is enabled", config.banners.source_lines)


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
