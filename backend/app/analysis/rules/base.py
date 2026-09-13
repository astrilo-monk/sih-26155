"""
Base class for security detection rules.

Each rule checks one specific security concern against the
normalized config model. Rules produce Finding objects when
they detect a problem.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from app.models.normalized import NormalizedConfig, Vendor
from app.models.findings import Finding, ComplianceMapping


class BaseRule(ABC):
    """
    Every security rule follows the same pattern:
    take a NormalizedConfig, return a list of Findings (empty if no issues).
    """

    # Subclasses set these
    rule_id: str = ""
    title: str = ""
    category: str = "general"

    # INTERIM(phase1) — everything tagged INTERIM(phase1) is the unknown-vendor
    # compatibility layer and is removed when the Phase 2 control catalog and
    # ControlResult statuses land.

    # INTERIM(phase1): True when the rule can FAIL because a value is missing
    absence_based: bool = False

    def evaluated_fields(self, config: NormalizedConfig) -> set[str]:
        """INTERIM(phase1): NormalizedConfig fields whose values this rule actually evaluated.

        Only consulted for unidentified vendors, to decide whether the config
        was assessed at all. A field the rule skipped (e.g. NTP authentication
        when no NTP server is known) is not evaluated.
        """
        return set()

    @staticmethod
    def _absence_is_evidence(config: NormalizedConfig) -> bool:
        """INTERIM(phase1): an empty field proves "not configured" only when a vendor parser read the config.

        For an unidentified vendor it only means "not found" — the line may
        simply not have been interpreted.
        """
        return config.device.vendor != Vendor.UNKNOWN

    @staticmethod
    def _applied_value(config: NormalizedConfig, field_path: str) -> list[str]:
        """INTERIM(phase1): values the adaptive layer actually wrote into ``field_path`` (lower-cased)."""
        return [
            str(m.final_value).lower()
            for m in config.ai_mappings
            if m.applied and m.normalized_field == field_path and m.final_value is not None
        ]

    @abstractmethod
    def evaluate(self, config: NormalizedConfig) -> list[Finding]:
        """Run this rule against a normalized config. Return findings."""
        ...

    def _make_finding(
        self,
        config: NormalizedConfig,
        severity,
        description: str,
        evidence_lines: list[str],
        line_numbers: list[int],
        security_impact: str,
        recommendation: str,
        compliance: list[ComplianceMapping] | None = None,
    ) -> Finding:
        """Helper to build a Finding with common fields pre-filled."""
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity,
            description=description,
            device_hostname=config.device.hostname,
            vendor=config.device.vendor.value,
            evidence_lines=evidence_lines,
            line_numbers=line_numbers,
            security_impact=security_impact,
            recommendation=recommendation,
            compliance=compliance or [],
            category=self.category,
        )

    def _get_evidence(self, config: NormalizedConfig, line_numbers: list[int]) -> list[str]:
        """Pull actual config lines for evidence display."""
        return config.get_evidence_lines(line_numbers)
