"""
Base class for control rules.

Every rule answers one catalog control (``rule_id`` is the control id) for one
normalized config and returns ControlResults:

* ``check`` — the detection logic; returns FAIL results, one per failing scope
  (a VTY range, an interface, an ACL entry …), each carrying what its Finding shows
* ``non_failure`` — when nothing failed: PASS with cited evidence, or
  NOT_CONFIGURED / UNKNOWN with a reason. A PASS without a supporting
  configuration line is never returned; it degrades to UNKNOWN.

Rules whose logic only exists for some vendors (``vendor_gated``) report the
other configs as NOT_CONFIGURED or UNKNOWN instead of passing silently. Phase 4
replaces the vendor gates with security facts.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Iterable, Optional

from app.controls.catalog import CONTROLS, Control, ControlKind
from app.models.normalized import NormalizedConfig, Vendor
from app.models.results import Assurance, ControlResult, Evidence, FailureDetail, Status

_SOURCE_ASSURANCE = {
    "learned_mapping": Assurance.CONFIRMED,
    "admin_confirmed": Assurance.CONFIRMED,
    "ai_auto_mapped": Assurance.AI_VERIFIED,
}
# Weakest first: a decision is only as strong as its weakest cited evidence
_ASSURANCE_STRENGTH = [
    Assurance.AI_VERIFIED, Assurance.HEURISTIC, Assurance.DEFAULT, Assurance.CONFIRMED, Assurance.PARSER,
]


class BaseRule(ABC):
    """Answers one catalog control for one NormalizedConfig."""

    rule_id: str = ""
    # True when ``check`` only has logic for ``evaluated_vendors``
    vendor_gated: bool = False
    evaluated_vendors: tuple[Vendor, ...] = (Vendor.CISCO_IOS, Vendor.FORTINET)

    @property
    def control(self) -> Control:
        return CONTROLS[self.rule_id]

    @property
    def title(self) -> str:
        return self.control.title

    @property
    def category(self) -> str:
        return self.control.category

    def evaluate(self, config: NormalizedConfig) -> list[ControlResult]:
        """FAIL results for every failing scope, otherwise exactly one other result."""
        failures = self.check(config)
        if failures:
            return failures
        if self.vendor_gated and config.device.vendor not in self.evaluated_vendors:
            return [self._not_evaluated(config)]
        return [self.non_failure(config)]

    @abstractmethod
    def check(self, config: NormalizedConfig) -> list[ControlResult]:
        """Detection logic: FAIL results only."""

    @abstractmethod
    def non_failure(self, config: NormalizedConfig) -> ControlResult:
        """Result when ``check`` found nothing, for a vendor the rule evaluates."""

    # ── result builders ─────────────────────────────────────────────────────

    def _fail(
        self,
        config: NormalizedConfig,
        severity,
        description: str,
        line_numbers: Iterable[int],
        security_impact: str,
        recommendation: str,
        scope: Optional[str] = None,
    ) -> ControlResult:
        evidence = self._evidence(config, line_numbers)
        return self._result(
            config, Status.FAIL, description, evidence, scope,
            assurance=self._assurance(config, evidence.line_numbers),
            failure=FailureDetail(severity, description, security_impact, recommendation),
        )

    def _pass(self, config: NormalizedConfig, reason: str, line_numbers: Iterable[int], scope: Optional[str] = None) -> ControlResult:
        evidence = self._evidence(config, line_numbers)
        if not evidence:
            return self._result(config, Status.UNKNOWN, f"{reason}, but no configuration line supports it", evidence, scope)
        return self._result(
            config, Status.PASS, reason, evidence, scope, assurance=self._assurance(config, evidence.line_numbers),
        )

    def _unknown(self, config: NormalizedConfig, reason: str, line_numbers: Iterable[int] = (), scope: Optional[str] = None) -> ControlResult:
        return self._result(config, Status.UNKNOWN, reason, self._evidence(config, line_numbers), scope)

    def _not_configured(self, config: NormalizedConfig, reason: str) -> ControlResult:
        return self._result(config, Status.NOT_CONFIGURED, reason, Evidence(), None)

    def _missing(self, config: NormalizedConfig, reason: str) -> ControlResult:
        """No relevant data: a relational question stays open, others are not configured."""
        if self.control.kind == ControlKind.RELATIONAL:
            return self._unknown(config, reason)
        return self._not_configured(config, reason)

    def _not_evaluated(self, config: NormalizedConfig) -> ControlResult:
        vendor = config.device.vendor
        if vendor == Vendor.UNKNOWN:
            touched = [
                m for m in config.ai_mappings
                if m.applied and m.normalized_field in self.control.normalized_fields
            ]
            if touched:
                fields = ", ".join(sorted({m.normalized_field for m in touched}))
                return self._unknown(
                    config,
                    f"A relevant setting was found ({fields}), but this control is not yet "
                    "evaluated for unidentified vendors",
                    [m.line_number for m in touched],
                )
            return self._missing(config, "No relevant setting was found in this configuration")
        return self._unknown(config, f"This control is not yet evaluated for {vendor.value} configurations")

    def _result(
        self,
        config: NormalizedConfig,
        status: Status,
        reason: str,
        evidence: Evidence,
        scope: Optional[str],
        assurance: Optional[Assurance] = None,
        failure: Optional[FailureDetail] = None,
    ) -> ControlResult:
        return ControlResult(
            control_id=self.rule_id,
            status=status,
            reason=reason,
            device_hostname=config.device.hostname,
            vendor=config.device.vendor.value,
            assurance=assurance,
            scope=scope,
            evidence=evidence,
            failure=failure,
        )

    # ── evidence helpers ────────────────────────────────────────────────────

    @staticmethod
    def _evidence(config: NormalizedConfig, line_numbers: Iterable[int]) -> Evidence:
        numbers = [n for n in line_numbers if 1 <= n <= len(config.raw_lines)]
        return Evidence(line_numbers=numbers, text=[config.raw_lines[n - 1] for n in numbers])

    @staticmethod
    def _lines(*objects) -> list[int]:
        """Source lines of parsed objects (interfaces, VTY lines, proposals …), in order."""
        return [n for obj in objects for n in obj.source_lines]

    @staticmethod
    def _lines_matching(config: NormalizedConfig, line_numbers: Iterable[int], pattern: str) -> list[int]:
        regex = re.compile(pattern, re.IGNORECASE)
        return [
            n for n in line_numbers
            if 1 <= n <= len(config.raw_lines) and regex.search(config.raw_lines[n - 1])
        ]

    @staticmethod
    def _field_lines(config: NormalizedConfig, field_path: str) -> list[int]:
        """Lines whose adaptive mapping wrote ``field_path``."""
        return [m.line_number for m in config.ai_mappings if m.applied and m.normalized_field == field_path]

    @classmethod
    def _with_field_lines(cls, config: NormalizedConfig, line_numbers: Iterable[int], *field_paths: str) -> list[int]:
        """``line_numbers`` plus the lines of adaptive mappings that wrote ``field_paths`` (ordered, unique)."""
        merged: list[int] = []
        for n in [*line_numbers, *(n for path in field_paths for n in cls._field_lines(config, path))]:
            if n not in merged:
                merged.append(n)
        return merged

    @staticmethod
    def _assurance(config: NormalizedConfig, line_numbers: list[int]) -> Optional[Assurance]:
        mapped = {
            m.line_number: _SOURCE_ASSURANCE[m.source]
            for m in config.ai_mappings if m.applied and m.source in _SOURCE_ASSURANCE
        }
        levels = {mapped[n] for n in line_numbers if n in mapped}
        if config.device.vendor != Vendor.UNKNOWN and (not line_numbers or any(n not in mapped for n in line_numbers)):
            levels.add(Assurance.PARSER)
        return min(levels, key=_ASSURANCE_STRENGTH.index) if levels else None

    # ── unknown-vendor absence gates (INTERIM(phase4): replaced by security facts) ──

    @staticmethod
    def _absence_is_evidence(config: NormalizedConfig) -> bool:
        """INTERIM(phase4): an empty field proves "not configured" only when a vendor parser read the config.

        For an unidentified vendor it only means "not found" — the line may
        simply not have been interpreted.
        """
        return config.device.vendor != Vendor.UNKNOWN

    @staticmethod
    def _applied_value(config: NormalizedConfig, field_path: str) -> list[str]:
        """INTERIM(phase4): values the adaptive layer actually wrote into ``field_path`` (lower-cased)."""
        return [
            str(m.final_value).lower()
            for m in config.ai_mappings
            if m.applied and m.normalized_field == field_path and m.final_value is not None
        ]
