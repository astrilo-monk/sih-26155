"""
Base class for security detection rules.

Each rule checks one specific security concern against the
normalized config model. Rules produce Finding objects when
they detect a problem.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from app.models.normalized import NormalizedConfig
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
