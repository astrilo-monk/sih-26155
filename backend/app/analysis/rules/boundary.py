"""
Boundary / data plane controls.

Firewall policies, ACLs and network-level settings that control what traffic
flows through the device.
"""

from __future__ import annotations

from app.analysis.rules.base import BaseRule
from app.models.findings import Severity
from app.models.normalized import NormalizedConfig, Vendor
from app.models.results import ControlResult


class OverlyPermissiveRulesRule(BaseRule):
    rule_id = "BOUNDARY-001"
    vendor_gated = True

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []

        if config.device.vendor == Vendor.CISCO_IOS:
            for acl in config.access_lists:
                for entry in acl.entries:
                    if (entry.action == "permit" and
                            self._is_any(entry.source) and
                            self._is_any(entry.destination) and
                            (entry.protocol is None or entry.protocol == "ip")):
                        results.append(self._fail(
                            config,
                            Severity.CRITICAL,
                            f"ACL '{acl.name}' contains a rule that permits all IP traffic "
                            "from any source to any destination. This effectively disables "
                            "the access control.",
                            entry.source_lines,
                            "An any-any permit rule defeats the purpose of having an ACL. "
                            "All traffic passes without restriction.",
                            f"Replace the any-any permit in '{acl.name}' with specific "
                            "source/destination/protocol rules.",
                            scope=f"acl {acl.name}",
                        ))

        elif config.device.vendor == Vendor.FORTINET:
            for policy in config.firewall_policies:
                if (policy.action == "accept" and
                        self._is_any(policy.src_address) and
                        self._is_any(policy.dst_address) and
                        self._has_all_services(policy.service)):
                    results.append(self._fail(
                        config,
                        Severity.CRITICAL,
                        f"Firewall policy '{policy.name or policy.policy_id}' allows all "
                        f"traffic from '{policy.src_interface}' to '{policy.dst_interface}' "
                        "with any source, any destination, and all services. This is an "
                        "open firewall policy.",
                        policy.source_lines,
                        "An any-any-all permit policy bypasses all firewall protection.",
                        "Create specific policies for needed traffic flows instead of "
                        "allowing everything.",
                        scope=f"firewall policy {policy.policy_id}",
                    ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        if config.device.vendor == Vendor.CISCO_IOS:
            entries = [entry for acl in config.access_lists for entry in acl.entries]
            if not entries:
                return self._missing(config, "No ACL entry is configured")
            return self._pass(config, "No ACL entry permits all IP traffic from any source to any destination", self._lines(*entries))

        policies = config.firewall_policies
        if not policies:
            return self._missing(config, "No firewall policy is configured")
        return self._pass(config, "No firewall policy accepts any source to any destination for all services", self._lines(*policies))

    @staticmethod
    def _is_any(addr: str | None) -> bool:
        if addr is None:
            return False
        return addr.strip().lower() in ("any", "all", "0.0.0.0", "0.0.0.0/0")

    @staticmethod
    def _has_all_services(services: list[str]) -> bool:
        return any(s.strip().upper() == "ALL" for s in services)


class IpSourceRoutingRule(BaseRule):
    """Presence-based: only an explicit "enabled" value fails, for every vendor."""
    rule_id = "BOUNDARY-002"

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        if config.services.ip_source_route is True:
            return [self._fail(
                config,
                Severity.MEDIUM,
                "IP source routing is enabled. This allows the sender of a packet "
                "to specify the route it takes through the network, potentially "
                "bypassing firewall rules and security controls.",
                config.services.source_lines,
                "Attackers can use source routing to bypass security devices "
                "and reach internal networks through unintended paths.",
                "Disable IP source routing: 'no ip source-route' (Cisco) or "
                "'set ip-src-routing disable' (FortiGate).",
            )]
        return []

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        if config.services.ip_source_route is False:
            lines = self._field_lines(config, "services.ip_source_route") or self._lines_matching(
                config, config.services.source_lines, r"source-route|src-routing",
            )
            return self._pass(config, "IP source routing is disabled", lines)
        if config.device.vendor == Vendor.UNKNOWN:
            return self._not_configured(config, "No IP source routing setting was found")
        return self._not_configured(
            config,
            "IP source routing is not stated; the platform default applies (vendor defaults are evaluated in Phase 4)",
        )


class DiscoveryProtocolExposureRule(BaseRule):
    rule_id = "BOUNDARY-003"
    vendor_gated = True

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []

        if config.device.vendor == Vendor.CISCO_IOS:
            # CDP is enabled globally by default on Cisco
            if config.services.cdp_globally_enabled is not False:
                for iface in config.interfaces:
                    if iface.is_wan and iface.cdp_enabled is not False:
                        results.append(self._fail(
                            config,
                            Severity.MEDIUM,
                            f"CDP is active on external interface '{iface.name}'. "
                            "CDP broadcasts device hostname, software version, IP addresses, "
                            "and hardware model to adjacent devices in cleartext.",
                            iface.source_lines,
                            "Device information leaked via CDP helps attackers fingerprint "
                            "the network and find version-specific vulnerabilities.",
                            f"Disable CDP on external interfaces: 'no cdp enable' on '{iface.name}'.",
                            scope=f"interface {iface.name}",
                        ))
                        break

        elif config.device.vendor == Vendor.FORTINET:
            for iface in config.interfaces:
                if iface.is_wan and iface.lldp_enabled is True:
                    results.append(self._fail(
                        config,
                        Severity.MEDIUM,
                        f"LLDP is enabled on WAN interface '{iface.name}'. "
                        "LLDP broadcasts device information to adjacent devices.",
                        iface.source_lines,
                        "Device information leakage on external interfaces.",
                        f"Disable LLDP on '{iface.name}': 'set lldp-transmission disable'.",
                        scope=f"interface {iface.name}",
                    ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        wan = [iface for iface in config.interfaces if iface.is_wan]

        if config.device.vendor == Vendor.CISCO_IOS:
            if config.services.cdp_globally_enabled is False:
                return self._pass(
                    config, "CDP is disabled globally",
                    self._lines_matching(config, config.services.source_lines, r"^\s*no cdp run"),
                )
            if not wan:
                return self._unknown(config, "No interface is identified as external")
            return self._pass(config, "CDP is disabled on every external interface", self._lines(*wan))

        if not wan:
            return self._unknown(config, "No interface is identified as WAN")
        unset = [iface for iface in wan if iface.lldp_enabled is None]
        if unset:
            return self._unknown(
                config,
                f"LLDP transmission is not set on WAN interface '{unset[0].name}'; the FortiOS default "
                "applies (vendor defaults are evaluated in Phase 4)",
                self._lines(*unset),
            )
        return self._pass(config, "LLDP transmission is disabled on every WAN interface", self._lines(*wan))


BOUNDARY_RULES: list[BaseRule] = [
    OverlyPermissiveRulesRule(),
    IpSourceRoutingRule(),
    DiscoveryProtocolExposureRule(),
]
