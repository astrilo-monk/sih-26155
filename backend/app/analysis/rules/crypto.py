"""
Cryptography controls.

Checks VPN/IPsec configurations for weak or deprecated encryption algorithms
and key exchange parameters.
"""

from __future__ import annotations

from app.analysis.rules.base import BaseRule
from app.models.findings import Severity
from app.models.normalized import NormalizedConfig
from app.models.results import ControlResult


# Algorithms considered weak or broken
WEAK_ENCRYPTION = {"des", "3des", "des-cbc", "3des-cbc"}
WEAK_HASH = {"md5", "md5-hmac", "esp-md5-hmac"}
WEAK_DH_GROUPS = {1, 2, 5}  # 768-bit, 1024-bit, 1536-bit


class WeakVpnCryptoRule(BaseRule):
    rule_id = "CRYPTO-001"

    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        results = []

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
                results.append(self._fail(
                    config,
                    Severity.HIGH,
                    f"VPN proposal '{proposal.name}' uses {', '.join(problems)}. "
                    "These algorithms have known weaknesses and can potentially be "
                    "broken by well-resourced attackers.",
                    proposal.source_lines,
                    "VPN traffic encrypted with weak algorithms may be decryptable, "
                    "exposing all data flowing through the tunnel.",
                    "Use AES-256 or AES-128 for encryption, SHA-256 or SHA-384 for "
                    "hashing, and DH group 14 (2048-bit) or higher.",
                    scope=f"proposal {proposal.name}",
                ))

        return results

    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        proposals = config.vpn.ipsec_proposals
        if not proposals:
            return self._not_configured(config, "No IPsec / IKE proposal is configured")
        unstated = [p for p in proposals if not p.encryption]
        if unstated:
            return self._unknown(
                config,
                f"Proposal '{unstated[0].name}' does not state its encryption; the platform default "
                "applies (vendor defaults are evaluated in Phase 4)",
                self._lines(*unstated),
            )
        return self._pass(config, "No proposal uses weak encryption, hashing or DH groups", self._lines(*proposals))

    @staticmethod
    def _dh_group_bits(group: int) -> int:
        return {1: 768, 2: 1024, 5: 1536}.get(group, 0)


CRYPTO_RULES: list[BaseRule] = [
    WeakVpnCryptoRule(),
]
