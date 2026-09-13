"""
Logging and time controls.

Whether the device forwards its logs off-box and synchronizes its clock from
an authenticated source — critical for incident response.
"""

from __future__ import annotations

from app.analysis.rules.base import BaseRule
from app.models.findings import Severity
from app.models.normalized import NormalizedConfig
from app.models.results import ControlResult


class NoRemoteSyslogRule(BaseRule):
    rule_id = "LOG-001"

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        if not config.logging.remote_hosts and self._absence_is_evidence(config):
            return [self._fail(
                config,
                Severity.HIGH,
                "No remote syslog server is configured. Logs are only stored "
                "locally on the device, where they can be lost during a reboot "
                "or deliberately cleared by an attacker.",
                config.logging.source_lines,
                "Without remote logging, forensic evidence is destroyed when the "
                "device reboots or when an attacker covers their tracks.",
                "Configure a remote syslog server to forward logs to a SIEM or "
                "log collector.",
            )]
        return []

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        hosts = config.logging.remote_hosts
        if not hosts:
            return self._not_configured(config, "No remote log destination was found")
        lines = [
            n for n in config.logging.source_lines
            if 1 <= n <= len(config.raw_lines) and any(host in config.raw_lines[n - 1] for host in hosts)
        ]
        return self._pass(
            config,
            f"Logs are forwarded to {', '.join(hosts)}",
            self._with_field_lines(config, lines or config.logging.source_lines, "logging.remote_hosts"),
        )


class NtpNotConfiguredRule(BaseRule):
    rule_id = "LOG-002"

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []
        absence_is_evidence = self._absence_is_evidence(config)
        # For an unidentified vendor, "not authenticated" needs an explicit value
        auth_explicitly_off = (
            absence_is_evidence
            or "false" in self._applied_value(config, "ntp.authentication_enabled")
        )

        if not config.ntp.servers:
            if not absence_is_evidence:
                return results
            results.append(self._fail(
                config,
                Severity.MEDIUM,
                "No NTP servers are configured. Without synchronized time, "
                "log timestamps will drift and become unreliable for correlating "
                "events across devices during incident investigation.",
                config.ntp.source_lines,
                "Inaccurate timestamps make forensic timeline reconstruction "
                "impossible across multiple devices.",
                "Configure at least two NTP servers for time synchronization.",
            ))
        elif not config.ntp.authentication_enabled and auth_explicitly_off:
            results.append(self._fail(
                config,
                Severity.MEDIUM,
                "NTP is configured but authentication is not enabled. An attacker "
                "could spoof NTP responses to manipulate the device's clock.",
                config.ntp.source_lines,
                "Clock manipulation can be used to bypass certificate validation, "
                "alter log timestamps, and disrupt time-sensitive security mechanisms.",
                "Enable NTP authentication with trusted keys.",
            ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        if not config.ntp.servers:
            return self._not_configured(config, "No NTP server was found")
        lines = self._with_field_lines(config, config.ntp.source_lines, "ntp.servers", "ntp.authentication_enabled")
        if config.ntp.authentication_enabled:
            return self._pass(config, "NTP servers are configured with authentication", lines)
        return self._unknown(
            config,
            "An NTP server was found, but whether NTP authentication is enabled could not be determined",
            lines,
        )


LOGGING_RULES: list[BaseRule] = [
    NoRemoteSyslogRule(),
    NtpNotConfiguredRule(),
]
