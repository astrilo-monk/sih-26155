"""
Cryptography security rules.

Checks VPN/IPsec configurations for weak or deprecated
encryption algorithms and key exchange parameters.
"""

from __future__ import annotations
from app.models.normalized import NormalizedConfig
from app.models.findings import Finding, Severity, ComplianceMapping
from app.analysis.rules.base import BaseRule


# Algorithms considered weak or broken
WEAK_ENCRYPTION = {"des", "3des", "des-cbc", "3des-cbc"}
WEAK_HASH = {"md5", "md5-hmac", "esp-md5-hmac"}
WEAK_DH_GROUPS = {1, 2, 5}  # 768-bit, 1024-bit, 1536-bit


class WeakVpnCryptoRule(BaseRule):
    rule_id = "CRYPTO-001"
    title = "Weak VPN/IPsec Cryptographic Algorithms"
    category = "cryptography"

    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        findings = []

        for proposal in config.vpn.ipsec_proposals:
            problems = []

            enc_lower = proposal.encryption.lower()
            hash_lower = proposal.hash_algorithm.lower()

            if any(weak in enc_lower for weak in WEAK_ENCRYPTION):
                problems.append(f"weak encryption '{proposal.encryption}'")

            if any(weak in hash_lower for weak in WEAK_HASH):
                problems.append(f"weak hash '{proposal.hash_algorithm}'")

            if proposal.dh_group in WEAK_DH_GROUPS:
                problems.append(f"weak DH group {proposal.dh_group} "
                                f"({self._dh_group_bits(proposal.dh_group)}-bit)")

            if problems:
                findings.append(self._make_finding(
                    config,
                    Severity.HIGH,
                    f"VPN proposal '{proposal.name}' uses {', '.join(problems)}. "
                    "These algorithms have known weaknesses and can potentially be "
                    "broken by well-resourced attackers.",
                    self._get_evidence(config, proposal.source_lines),
                    proposal.source_lines,
                    "VPN traffic encrypted with weak algorithms may be decryptable, "
                    "exposing all data flowing through the tunnel.",
                    "Use AES-256 or AES-128 for encryption, SHA-256 or SHA-384 for "
                    "hashing, and DH group 14 (2048-bit) or higher.",
                    [
                        ComplianceMapping("CIS", "2.3.1", "Use strong VPN cryptography"),
                        ComplianceMapping("NIST_800_53", "SC-13", "Cryptographic Protection"),
                        ComplianceMapping("NIST_800_53", "SC-8", "Transmission Confidentiality"),
                    ],
                ))

        return findings

    @staticmethod
    def _dh_group_bits(group: int) -> int:
        return {1: 768, 2: 1024, 5: 1536}.get(group, 0)


CRYPTO_RULES: list[BaseRule] = [
    WeakVpnCryptoRule(),
]
