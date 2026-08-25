"""
Logging and monitoring security rules.

These check whether the device is properly logging events and
synchronizing its clock — critical for incident response.
"""

from __future__ import annotations
from app.models.normalized import NormalizedConfig, Vendor
from app.models.findings import Finding, Severity, ComplianceMapping
from app.analysis.rules.base import BaseRule


class NoRemoteSyslogRule(BaseRule):
    rule_id = "LOG-001"
    title = "No Remote Syslog Server Configured"
    category = "logging"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        if not config.logging.remote_hosts:
            return [self._make_finding(
                config,
                Severity.HIGH,
                "No remote syslog server is configured. Logs are only stored "
                "locally on the device, where they can be lost during a reboot "
                "or deliberately cleared by an attacker.",
                self._get_evidence(config, config.logging.source_lines),
                config.logging.source_lines,
                "Without remote logging, forensic evidence is destroyed when the "
                "device reboots or when an attacker covers their tracks.",
                "Configure a remote syslog server to forward logs to a SIEM or "
                "log collector.",
                [
                    ComplianceMapping("CIS", "1.4.1", "Configure remote syslog"),
                    ComplianceMapping("NIST_800_53", "AU-2", "Event Logging"),
                    ComplianceMapping("NIST_800_53", "AU-4", "Audit Log Storage Capacity"),
                ],
            )]
        return []


class NtpNotConfiguredRule(BaseRule):
    rule_id = "LOG-002"
    title = "NTP Not Configured or Unauthenticated"
    category = "logging"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        if not config.ntp.servers:
            findings.append(self._make_finding(
                config,
                Severity.MEDIUM,
                "No NTP servers are configured. Without synchronized time, "
                "log timestamps will drift and become unreliable for correlating "
                "events across devices during incident investigation.",
                self._get_evidence(config, config.ntp.source_lines),
                config.ntp.source_lines,
                "Inaccurate timestamps make forensic timeline reconstruction "
                "impossible across multiple devices.",
                "Configure at least two NTP servers for time synchronization.",
                [
                    ComplianceMapping("CIS", "1.4.3", "Configure NTP"),
                    ComplianceMapping("NIST_800_53", "AU-8", "Time Stamps"),
                ],
            ))
        elif not config.ntp.authentication_enabled:
            findings.append(self._make_finding(
                config,
                Severity.MEDIUM,
                "NTP is configured but authentication is not enabled. An attacker "
                "could spoof NTP responses to manipulate the device's clock.",
                self._get_evidence(config, config.ntp.source_lines),
                config.ntp.source_lines,
                "Clock manipulation can be used to bypass certificate validation, "
                "alter log timestamps, and disrupt time-sensitive security mechanisms.",
                "Enable NTP authentication with trusted keys.",
                [
                    ComplianceMapping("CIS", "1.4.4", "Set NTP authentication"),
                    ComplianceMapping("NIST_800_53", "AU-8(1)", "Synchronization with Authoritative Time Source"),
                ],
            ))

        return findings


LOGGING_RULES: list[BaseRule] = [
    NoRemoteSyslogRule(),
    NtpNotConfiguredRule(),
]
