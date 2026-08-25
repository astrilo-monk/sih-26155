"""
Boundary / data plane security rules.

These check firewall policies, ACLs, and network-level settings
that control what traffic flows through the device.
"""

from __future__ import annotations
from app.models.normalized import NormalizedConfig, Vendor
from app.models.findings import Finding, Severity, ComplianceMapping
from app.analysis.rules.base import BaseRule


class OverlyPermissiveRulesRule(BaseRule):
    rule_id = "BOUNDARY-001"
    title = "Overly Permissive Firewall/ACL Rules"
    category = "boundary"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        if config.device.vendor == Vendor.CISCO_IOS:
            for acl in config.access_lists:
                for entry in acl.entries:
                    if (entry.action == "permit" and
                            self._is_any(entry.source) and
                            self._is_any(entry.destination) and
                            (entry.protocol is None or entry.protocol == "ip")):
                        findings.append(self._make_finding(
                            config,
                            Severity.CRITICAL,
                            f"ACL '{acl.name}' contains a rule that permits all IP traffic "
                            "from any source to any destination. This effectively disables "
                            "the access control.",
                            self._get_evidence(config, entry.source_lines),
                            entry.source_lines,
                            "An any-any permit rule defeats the purpose of having an ACL. "
                            "All traffic passes without restriction.",
                            f"Replace the any-any permit in '{acl.name}' with specific "
                            "source/destination/protocol rules.",
                            [
                                ComplianceMapping("CIS", "2.3.1", "Restrict ACL rules"),
                                ComplianceMapping("NIST_800_53", "AC-4", "Information Flow Enforcement"),
                                ComplianceMapping("NIST_800_53", "SC-7", "Boundary Protection"),
                            ],
                        ))

        elif config.device.vendor == Vendor.FORTINET:
            for policy in config.firewall_policies:
                if (policy.action == "accept" and
                        self._is_any(policy.src_address) and
                        self._is_any(policy.dst_address) and
                        self._has_all_services(policy.service)):
                    findings.append(self._make_finding(
                        config,
                        Severity.CRITICAL,
                        f"Firewall policy '{policy.name or policy.policy_id}' allows all "
                        f"traffic from '{policy.src_interface}' to '{policy.dst_interface}' "
                        "with any source, any destination, and all services. This is an "
                        "open firewall policy.",
                        self._get_evidence(config, policy.source_lines),
                        policy.source_lines,
                        "An any-any-all permit policy bypasses all firewall protection.",
                        "Create specific policies for needed traffic flows instead of "
                        "allowing everything.",
                        [
                            ComplianceMapping("CIS", "2.2.1", "Restrict firewall policies"),
                            ComplianceMapping("NIST_800_53", "AC-4", "Information Flow Enforcement"),
                            ComplianceMapping("NIST_800_53", "SC-7", "Boundary Protection"),
                        ],
                    ))

        return findings

    @staticmethod
    def _is_any(addr: str | None) -> bool:
        if addr is None:
            return False
        return addr.strip().lower() in ("any", "all", "0.0.0.0", "0.0.0.0/0")

    @staticmethod
    def _has_all_services(services: list[str]) -> bool:
        return any(s.strip().upper() == "ALL" for s in services)


class IpSourceRoutingRule(BaseRule):
    rule_id = "BOUNDARY-002"
    title = "IP Source Routing Enabled"
    category = "boundary"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        if config.services.ip_source_route is True:
            return [self._make_finding(
                config,
                Severity.MEDIUM,
                "IP source routing is enabled. This allows the sender of a packet "
                "to specify the route it takes through the network, potentially "
                "bypassing firewall rules and security controls.",
                self._get_evidence(config, config.services.source_lines),
                config.services.source_lines,
                "Attackers can use source routing to bypass security devices "
                "and reach internal networks through unintended paths.",
                "Disable IP source routing: 'no ip source-route' (Cisco) or "
                "'set ip-src-routing disable' (FortiGate).",
                [
                    ComplianceMapping("CIS", "2.2.1", "Disable IP source routing"),
                    ComplianceMapping("NIST_800_53", "SC-7", "Boundary Protection"),
                ],
            )]
        return []


class DiscoveryProtocolExposureRule(BaseRule):
    rule_id = "BOUNDARY-003"
    title = "Discovery Protocol (CDP/LLDP) Enabled on External Interface"
    category = "boundary"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        if config.device.vendor == Vendor.CISCO_IOS:
            # CDP is enabled globally by default on Cisco
            if config.services.cdp_globally_enabled is not False:
                for iface in config.interfaces:
                    if iface.is_wan and iface.cdp_enabled is not False:
                        findings.append(self._make_finding(
                            config,
                            Severity.MEDIUM,
                            f"CDP is active on external interface '{iface.name}'. "
                            "CDP broadcasts device hostname, software version, IP addresses, "
                            "and hardware model to adjacent devices in cleartext.",
                            self._get_evidence(config, iface.source_lines),
                            iface.source_lines,
                            "Device information leaked via CDP helps attackers fingerprint "
                            "the network and find version-specific vulnerabilities.",
                            f"Disable CDP on external interfaces: 'no cdp enable' on '{iface.name}'.",
                            [
                                ComplianceMapping("CIS", "2.1.1", "Disable CDP on external interfaces"),
                                ComplianceMapping("NIST_800_53", "CM-7", "Least Functionality"),
                            ],
                        ))
                        break

        elif config.device.vendor == Vendor.FORTINET:
            for iface in config.interfaces:
                if iface.is_wan and iface.lldp_enabled is True:
                    findings.append(self._make_finding(
                        config,
                        Severity.MEDIUM,
                        f"LLDP is enabled on WAN interface '{iface.name}'. "
                        "LLDP broadcasts device information to adjacent devices.",
                        self._get_evidence(config, iface.source_lines),
                        iface.source_lines,
                        "Device information leakage on external interfaces.",
                        f"Disable LLDP on '{iface.name}': 'set lldp-transmission disable'.",
                        [
                            ComplianceMapping("CIS", "2.1.1", "Disable LLDP on external interfaces"),
                            ComplianceMapping("NIST_800_53", "CM-7", "Least Functionality"),
                        ],
                    ))

        return findings


BOUNDARY_RULES: list[BaseRule] = [
    OverlyPermissiveRulesRule(),
    IpSourceRoutingRule(),
    DiscoveryProtocolExposureRule(),
]
