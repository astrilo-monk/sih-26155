"""
Phase 3 — Confidence-based interpretation and safe NormalizedConfig enrichment.

Pipeline::

    AI Interpretation          (Phase 2 — InterpretationResult list)
           ↓
    InterpretationValidator    — validates field / type / evidence / scheme
           ↓
    ConfidenceDecision         — numeric ≥ 0.85 / 0.50 / < 0.50  →  HIGH / MEDIUM / LOW
           ↓
    AdaptiveMapper             — safe NormalizedConfig enrichment
           ↓
    NormalizedConfig           (enriched + ``ai_mappings`` audit trail)
           ↓
    Compliance Engine          (existing deterministic rules — sole authority)

The same mapper also applies confirmed learned mappings (Phase 5) and
administrator decisions (Phase 4), so there is exactly one place where
adaptive values are written into ``NormalizedConfig``.

Safety guarantees
-----------------
* An uncertain (MEDIUM / LOW) interpretation **never** populates
  ``NormalizedConfig``, therefore it can never cause a vulnerable
  configuration to appear compliant.
* Even HIGH confidence is only written to a field after the
  ``InterpretationValidator`` confirms the field is a registered scalar,
  the extracted value converts to the expected type, and the reasoning
  (evidence) is non-empty.  A failed HIGH maps to ``needs_review``.
* AI and learned mappings never overwrite a value that is already set to
  something different (e.g. by the vendor parser) — the conflict goes to
  review instead. Only an explicit administrator decision may overwrite.
* Every AI-touched line produces exactly one ``AIFieldMapping`` entry
  in ``config.ai_mappings`` for full auditability.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Iterable, Optional

from app.ai.interpretation_schemas import (
    InterpretationResult,
    InterpretationStatus,
)
from app.models.field_catalog import (  # re-exported: the catalog is the single source of truth
    BOOL_TYPES,
    FIELD_REGISTRY,
    INT_TYPES,
    TYPE_BOOL,
    TYPE_INT,
    TYPE_LIST_STR,
    TYPE_OPTIONAL_BOOL,
    TYPE_OPTIONAL_INT,
    TYPE_OPTIONAL_STR,
    TYPE_STR,
    FieldTypeInfo,
    convert_bool,
    convert_int,
    convert_list_str,
    convert_str,
)
from app.models.normalized import (
    NormalizedConfig,
    AIFieldMapping,
    UnrecognizedLine,
)

if TYPE_CHECKING:
    from app.adaptive.matcher import MappingMatch
    from app.db.mappings import LearnedMapping

logger = logging.getLogger(__name__)


# ── Dispositions ──────────────────────────────────────────────────────────────

SOURCE_AI_AUTO_MAPPED = "ai_auto_mapped"
SOURCE_LEARNED_MAPPING = "learned_mapping"
SOURCE_ADMIN_CONFIRMED = "admin_confirmed"
SOURCE_NEEDS_REVIEW = "needs_review"
SOURCE_NEEDS_TRAINING = "needs_training"
SOURCE_REJECTED = "rejected"

REVIEWABLE_SOURCES = frozenset({SOURCE_NEEDS_REVIEW, SOURCE_NEEDS_TRAINING})

# Tier labels for records that did not come from an AI confidence score
TIER_CONFIRMED = "confirmed"
TIER_AMBIGUOUS = "ambiguous"


# ── Confidence tier thresholds ────────────────────────────────────────────────

HIGH_THRESHOLD: float = 0.85
MEDIUM_THRESHOLD: float = 0.50


class ConfidenceTier(str, Enum):
    """Confidence tiers used by Phase 3 to decide disposition."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def determine_tier(numeric_confidence: float) -> ConfidenceTier:
    """Map a numeric confidence score to a :class:`ConfidenceTier`."""
    if numeric_confidence >= HIGH_THRESHOLD:
        return ConfidenceTier.HIGH
    if numeric_confidence >= MEDIUM_THRESHOLD:
        return ConfidenceTier.MEDIUM
    return ConfidenceTier.LOW


def format_value(value: Any) -> Optional[str]:
    """Render a normalized value for the audit trail."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def _add_source_line(obj: Any, line_num: int) -> None:
    """Append a line number to an object's ``source_lines`` if it has one."""
    if hasattr(obj, "source_lines"):
        if line_num not in obj.source_lines:
            obj.source_lines.append(line_num)


# ── Validation ────────────────────────────────────────────────────────────────

@dataclass
class ValidationResult:
    """Result of validating an AI interpretation for safe auto-mapping."""
    is_valid: bool
    reason: str
    converted_value: Optional[Any] = None
    field_info: Optional[FieldTypeInfo] = None


def _field_error(normalized_field: str) -> Optional[ValidationResult]:
    """Return a failed ValidationResult if the field is not a settable scalar."""
    if normalized_field == "unknown":
        return ValidationResult(
            is_valid=False,
            reason="AI returned normalized_field='unknown' — no field to map",
        )
    if normalized_field in FIELD_REGISTRY:
        return None
    if "[]" in normalized_field:
        return ValidationResult(
            is_valid=False,
            reason=(
                f"'{normalized_field}' is a container / "
                "list field requiring additional context — cannot auto-map"
            ),
        )
    return ValidationResult(
        is_valid=False,
        reason=f"'{normalized_field}' is not a registered settable scalar field",
    )


class InterpretationValidator:
    """
    Validates that an AI interpretation can safely map to a
    ``NormalizedConfig`` scalar field.

    Checks (in order):

    1. Phase 2 status is ``interpreted`` (not ``unknown`` / ``ai_unavailable``).
    2. ``normalized_field`` is a registered scalar field — not ``unknown``,
       not a container / list field that needs additional context.
    3. ``reasoning`` is non-empty (evidence threshold).
    4. ``extracted_value`` is provided (not ``None``).
    5. ``extracted_value`` converts to the field's expected type.
    """

    @staticmethod
    def validate(interpretation: InterpretationResult) -> ValidationResult:
        # 1 — status
        if interpretation.status != InterpretationStatus.INTERPRETED:
            return ValidationResult(
                is_valid=False,
                reason=(
                    f"Interpretation status is '{interpretation.status.value}' "
                    "— expected 'interpreted'"
                ),
            )

        # 2 — field is a registered scalar
        error = _field_error(interpretation.normalized_field)
        if error is not None:
            return error

        # 3 — evidence
        if not interpretation.reasoning or not interpretation.reasoning.strip():
            return ValidationResult(
                is_valid=False,
                reason="No reasoning provided — insufficient evidence",
            )

        # 4, 5 — value present and of the expected type
        return InterpretationValidator.validate_value(
            interpretation.normalized_field, interpretation.extracted_value,
        )

    @staticmethod
    def validate_value(normalized_field: str, extracted_value: Optional[str]) -> ValidationResult:
        """Validate a field/value pair regardless of where it came from."""
        error = _field_error(normalized_field)
        if error is not None:
            return error
        field_info = FIELD_REGISTRY[normalized_field]

        if extracted_value is None:
            return ValidationResult(
                is_valid=False,
                reason="No extracted value provided",
            )

        converted = field_info.convert(extracted_value)

        if field_info.type_category == TYPE_LIST_STR:
            if not converted:
                return ValidationResult(
                    is_valid=False,
                    reason=(
                        f"Extracted value '{extracted_value}' could "
                        "not be parsed into a non-empty list"
                    ),
                )
            return ValidationResult(
                is_valid=True, reason="Valid", converted_value=converted, field_info=field_info,
            )

        if converted is None:
            return ValidationResult(
                is_valid=False,
                reason=(
                    f"Value '{extracted_value}' cannot be converted "
                    f"to expected type '{field_info.type_category}'"
                ),
            )

        return ValidationResult(
            is_valid=True, reason="Valid", converted_value=converted, field_info=field_info,
        )


# ── Safe field writes ─────────────────────────────────────────────────────────

@dataclass
class WriteResult:
    applied: bool
    reason: str
    final_value: Optional[str] = None


def _dataclass_default(obj: Any, attr: str) -> Any:
    if dataclasses.is_dataclass(obj):
        for f in dataclasses.fields(obj):
            if f.name == attr:
                if f.default is not dataclasses.MISSING:
                    return f.default
                if f.default_factory is not dataclasses.MISSING:
                    return f.default_factory()
    return None


def write_field(
    config: NormalizedConfig,
    validation: ValidationResult,
    line_number: int,
    force: bool = False,
) -> WriteResult:
    """
    Write a validated value into *config*.

    List fields are merged. A scalar that already holds a different,
    non-default value is left untouched unless ``force`` is set (explicit
    administrator decision) — a conflicting interpretation must be reviewed,
    not guessed.
    """
    field_info = validation.field_info
    value = validation.converted_value
    parent = field_info.get_parent(config)
    attr = field_info.attr_name

    if field_info.type_category == TYPE_LIST_STR:
        existing: list[str] = getattr(parent, attr, None) or []
        for v in value:
            if v not in existing:
                existing.append(v)
        setattr(parent, attr, existing)
    else:
        current = getattr(parent, attr, None)
        if not force and current != _dataclass_default(parent, attr) and current != value:
            return WriteResult(
                applied=False,
                reason=f"conflicts with existing value '{format_value(current)}'",
            )
        setattr(parent, attr, value)

    _add_source_line(parent, line_number)
    return WriteResult(applied=True, reason="Applied", final_value=format_value(value))


# ── Confidence decision ───────────────────────────────────────────────────────

@dataclass
class ConfidenceDecision:
    """Numeric confidence score and resulting tier for one interpretation."""
    numeric_confidence: float
    tier: ConfidenceTier


_TIER_RANK = {ConfidenceTier.LOW: 0, ConfidenceTier.MEDIUM: 1, ConfidenceTier.HIGH: 2}
_TIER_CEILING = {
    ConfidenceTier.HIGH: 1.0,
    ConfidenceTier.MEDIUM: round(HIGH_THRESHOLD - 0.01, 2),
    ConfidenceTier.LOW: round(MEDIUM_THRESHOLD - 0.01, 2),
}


def make_confidence_decision(interpretation: InterpretationResult) -> ConfidenceDecision:
    """Derive a numeric confidence score and :class:`ConfidenceTier` from an
    :class:`InterpretationResult`.

    Uses ``numeric_confidence`` when the AI provides it; otherwise falls back
    to a deterministic mapping from the string :class:`ConfidenceLevel`.
    When the stated level and the number disagree, the lower tier wins —
    an inconsistent answer is never treated as the more confident one.
    """
    numeric = interpretation.effective_confidence
    tier = determine_tier(numeric)
    stated = ConfidenceTier(interpretation.confidence.value)
    if _TIER_RANK[stated] < _TIER_RANK[tier]:
        tier = stated
        numeric = min(numeric, _TIER_CEILING[tier])
    return ConfidenceDecision(numeric_confidence=numeric, tier=tier)


# ── Evidence assessment ───────────────────────────────────────────────────────

EVIDENCE_SUPPORTED = "supported"
EVIDENCE_UNVERIFIED = "unverified"
EVIDENCE_CONTRADICTED = "contradicted"

_TOKEN_SPLIT = re.compile(r"[\s=:;,{}()\[\]\"'<>]+")
_WORD_SPLIT = re.compile(r"[-_./]")
_NEGATIVE_WORDS = frozenset({
    "no", "not", "never", "none", "disable", "disabled", "false", "off",
    "deny", "denied", "shutdown", "block", "blocked", "inactive",
})
_POSITIVE_WORDS = frozenset({
    "yes", "enable", "enabled", "true", "on", "permit", "permitted",
    "allow", "allowed", "active", "start",
})


@dataclass
class EvidenceAssessment:
    """Whether the raw line itself supports an interpreted value."""
    status: str
    reason: str = ""


def _normalize_text(text: Optional[str]) -> str:
    return " ".join((text or "").split()).lower()


def line_polarity(text: str) -> Optional[bool]:
    """
    Vendor-neutral on/off reading of a line: every negating word flips the
    state (``disable-ssh no`` → on, ``no ip source-route`` → off). Returns
    ``None`` when the line contains no polarity words at all.
    """
    state, seen = True, False
    for token in _TOKEN_SPLIT.split(text.lower()):
        for word in _WORD_SPLIT.split(token):
            if word in _NEGATIVE_WORDS:
                state, seen = not state, True
            elif word in _POSITIVE_WORDS:
                seen = True
    return state if seen else None


def assess_evidence(
    normalized_field: str,
    extracted_value: Optional[str],
    raw_line: str,
    value_evidence: Optional[str] = None,
) -> EvidenceAssessment:
    """
    Check an interpreted value against the raw line, independent of vendor.

    * cited evidence must occur in the line
    * text and list values must appear in the line
    * on/off values must not contradict the line's wording
    * numbers must appear in the line when evidence was cited
    """
    info = FIELD_REGISTRY.get(normalized_field)
    if info is None or extracted_value is None:
        return EvidenceAssessment(EVIDENCE_UNVERIFIED)

    line = _normalize_text(raw_line)
    if value_evidence and value_evidence.strip():
        cited = _normalize_text(value_evidence).strip("\"'")
        if cited and cited not in line:
            return EvidenceAssessment(
                EVIDENCE_CONTRADICTED, f"cited evidence '{value_evidence.strip()}' does not occur in the line",
            )

    if info.type_category in BOOL_TYPES:
        value = info.convert(extracted_value)
        polarity = line_polarity(line)
        if value is None or polarity is None:
            return EvidenceAssessment(EVIDENCE_UNVERIFIED)
        if polarity != value:
            return EvidenceAssessment(
                EVIDENCE_CONTRADICTED,
                f"the line's wording indicates '{format_value(polarity)}', not '{format_value(value)}'",
            )
        return EvidenceAssessment(EVIDENCE_SUPPORTED)

    if info.type_category in INT_TYPES:
        value = info.convert(extracted_value)
        if value is not None and value in {int(n) for n in re.findall(r"\d+", line)}:
            return EvidenceAssessment(EVIDENCE_SUPPORTED)
        if value_evidence:
            return EvidenceAssessment(EVIDENCE_CONTRADICTED, f"value '{extracted_value}' does not appear in the line")
        return EvidenceAssessment(EVIDENCE_UNVERIFIED)

    converted = info.convert(extracted_value)
    values = converted if isinstance(converted, list) else [converted]
    for v in values:
        needle = _normalize_text(v).strip("\"'")
        if needle and needle not in line:
            return EvidenceAssessment(EVIDENCE_CONTRADICTED, f"value '{v}' does not appear in the line")
    return EvidenceAssessment(EVIDENCE_SUPPORTED)


# ── AdaptiveMapper — safe NormalizedConfig enrichment ─────────────────────────

class AdaptiveMapper:
    """
    Converts validated interpretations into ``NormalizedConfig`` field
    values following Phase 3 confidence-tier rules.

    ┌──────────────┬────────────────────────────────────────────────────┐
    │ Tier         │ Disposition                                         │
    ├──────────────┼────────────────────────────────────────────────────┤
    │ HIGH ≥ 0.85  │ If valid → write to config, mark ``ai_auto_mapped`` │
    │              │ If invalid → ``needs_review`` (no config mutation)   │
    │ MEDIUM 0.5–0.85 │ ``needs_review`` (no config mutation)          │
    │ LOW < 0.50   │ ``needs_training`` (no config mutation)            │
    └──────────────┴────────────────────────────────────────────────────┘
    """

    def __init__(self, validator: Optional[InterpretationValidator] = None):
        self.validator = validator or InterpretationValidator()

    def map_interpretations(
        self,
        config: NormalizedConfig,
        interpretations: list[InterpretationResult],
    ) -> list[AIFieldMapping]:
        """
        Apply confidence-based interpretation to *config* (modified in-place).

        * HIGH-valid interpretations are written to their target fields
          and tracked in ``config.ai_mappings`` with ``source='ai_auto_mapped'``.
        * Every interpretation — regardless of tier — produces an
          ``AIFieldMapping`` audit entry appended to ``config.ai_mappings``.
        * MEDIUM / LOW interpretations never mutate config fields.

        Returns the list of audit records (same objects appended to
        ``config.ai_mappings``).
        """
        audit_records = [self.process_interpretation(config, interp) for interp in interpretations]
        config.ai_mappings.extend(audit_records)
        return audit_records

    # ── AI interpretations ──────────────────────────────────────────────────

    def process_interpretation(
        self,
        config: NormalizedConfig,
        interp: InterpretationResult,
        learned_candidate_fields: Optional[Iterable[str]] = None,
        auto_apply: bool = True,
    ) -> AIFieldMapping:
        """
        Decide and apply one AI interpretation; does not touch ``ai_mappings``.

        ``learned_candidate_fields`` — fields of confirmed learned mappings
        whose patterns resemble this line. A HIGH interpretation that maps the
        line somewhere else conflicts with confirmed knowledge and is reviewed.
        ``auto_apply=False`` — a valid HIGH interpretation is reviewed too, never written.
        """
        # Step 1 — validate
        validation = self.validator.validate(interp)

        # Step 2 — confidence decision
        decision = make_confidence_decision(interp)
        confidence = decision.numeric_confidence
        tier = decision.tier

        # Step 3 — evidence (only meaningful for a valid field/value)
        evidence = (
            assess_evidence(interp.normalized_field, interp.extracted_value, interp.raw_line, interp.value_evidence)
            if validation.is_valid else EvidenceAssessment(EVIDENCE_UNVERIFIED)
        )
        note = f"; note: {evidence.reason}" if evidence.status == EVIDENCE_CONTRADICTED else ""

        # Step 4 — dispatch by tier + validity
        if tier == ConfidenceTier.HIGH:
            if validation.is_valid and validation.field_info is not None:
                concern = self._high_confidence_concern(interp, evidence, learned_candidate_fields)
                if concern:
                    return self._needs_review(
                        interp, min(confidence, _TIER_CEILING[ConfidenceTier.MEDIUM]), ConfidenceTier.MEDIUM,
                        f"Downgraded from HIGH confidence: {concern}",
                    )
                if not auto_apply:
                    return self._needs_review(
                        interp, confidence, tier,
                        "HIGH confidence — AI interpretations are never applied without administrator review",
                    )
                return self._auto_map(config, interp, validation, confidence)
            # HIGH but invalid → needs_review
            return self._needs_review(
                interp, confidence, tier,
                f"HIGH confidence but validation failed: {validation.reason}",
            )

        if tier == ConfidenceTier.MEDIUM:
            # MEDIUM never writes to config — even if valid
            return self._needs_review(
                interp, confidence, tier,
                f"MEDIUM confidence — requires admin review before applying{note}",
            )

        # LOW
        if interp.status == InterpretationStatus.AI_UNAVAILABLE:
            reason = (
                "AI interpretation unavailable — this is not a confidence judgement; "
                "map the line manually or rescan when AI is available"
            )
        else:
            reason = f"LOW confidence — not applied; needs training{note}"
        return self._needs_training(interp, confidence, tier, reason)

    @staticmethod
    def _high_confidence_concern(
        interp: InterpretationResult,
        evidence: EvidenceAssessment,
        learned_candidate_fields: Optional[Iterable[str]],
    ) -> Optional[str]:
        """Deterministic reasons a HIGH interpretation must not be applied automatically."""
        if evidence.status == EVIDENCE_CONTRADICTED:
            return evidence.reason
        fields = set(learned_candidate_fields or ())
        if fields and interp.normalized_field not in fields:
            return "similar confirmed learned mapping(s) map this syntax to " + ", ".join(sorted(fields))
        return None

    # Kept for callers written against the original Phase 3 API
    _process_one = process_interpretation

    def _auto_map(
        self,
        config: NormalizedConfig,
        interp: InterpretationResult,
        validation: ValidationResult,
        confidence: float,
    ) -> AIFieldMapping:
        """Apply a validated HIGH-confidence interpretation to the config."""
        try:
            write = write_field(config, validation, interp.line_number)
        except Exception as e:
            logger.warning(
                "Auto-map assignment failed for line %d despite valid validation: %s",
                interp.line_number, e,
            )
            return self._needs_review(
                interp, confidence, ConfidenceTier.HIGH,
                f"HIGH confidence but assignment failed: {e}",
            )

        if not write.applied:
            return self._needs_review(
                interp, confidence, ConfidenceTier.HIGH,
                f"HIGH confidence but {write.reason}",
            )

        logger.info(
            "Auto-mapped: line %d → %s = %r (confidence=%.2f, tier=high)",
            interp.line_number, interp.normalized_field, write.final_value, confidence,
        )
        return self._from_interpretation(
            interp, confidence, ConfidenceTier.HIGH.value, SOURCE_AI_AUTO_MAPPED,
            final_value=write.final_value,
            reason="HIGH confidence and validated — applied automatically",
        )

    def _needs_review(
        self,
        interp: InterpretationResult,
        confidence: float,
        tier: ConfidenceTier,
        reason: str,
    ) -> AIFieldMapping:
        """Create a ``needs_review`` audit record (value NOT written to config)."""
        logger.info(
            "Routing line %d to review: %s (confidence=%.2f, tier=%s)",
            interp.line_number, reason, confidence, tier.value,
        )
        return self._from_interpretation(
            interp, confidence, tier.value, SOURCE_NEEDS_REVIEW, reason=reason,
        )

    def _needs_training(
        self,
        interp: InterpretationResult,
        confidence: float,
        tier: ConfidenceTier,
        reason: str = "LOW confidence — not applied; needs training",
    ) -> AIFieldMapping:
        """Create a ``needs_training`` audit record (value NOT written to config)."""
        logger.info(
            "Routing line %d to training: low confidence=%.2f",
            interp.line_number, confidence,
        )
        return self._from_interpretation(
            interp, confidence, tier.value, SOURCE_NEEDS_TRAINING, reason=reason,
        )

    @staticmethod
    def _from_interpretation(
        interp: InterpretationResult,
        confidence: float,
        tier: str,
        source: str,
        final_value: Optional[str] = None,
        reason: str = "",
    ) -> AIFieldMapping:
        return AIFieldMapping(
            line_number=interp.line_number,
            raw_line=interp.raw_line,
            normalized_field=interp.normalized_field,
            extracted_value=interp.extracted_value,
            confidence=confidence,
            confidence_tier=tier,
            reasoning=interp.reasoning,
            source=source,
            status=interp.status.value,
            likely_vendor=interp.likely_vendor,
            security_concept=interp.security_concept,
            final_value=final_value,
            reason=reason,
        )

    # ── Learned mappings (Phase 5) ──────────────────────────────────────────

    def apply_learned(
        self,
        config: NormalizedConfig,
        line: UnrecognizedLine,
        match: "MappingMatch",
    ) -> AIFieldMapping:
        """Apply a reliable learned-mapping match (no AI involved)."""
        mapping = match.mapping
        record = AIFieldMapping(
            line_number=line.line_number,
            raw_line=line.raw_line,
            normalized_field=mapping.normalized_field,
            extracted_value=match.value,
            confidence=mapping.confidence,
            confidence_tier=TIER_CONFIRMED,
            reasoning=f"Matched confirmed learned mapping #{mapping.id}: '{mapping.command_pattern}'",
            source=SOURCE_NEEDS_REVIEW,
            status="learned",
            likely_vendor=mapping.vendor or "",
            security_concept=mapping.concept,
            mapping_id=mapping.id,
        )

        validation = self.validator.validate_value(mapping.normalized_field, match.value)
        if not validation.is_valid:
            record.reason = f"Learned mapping matched but the value is invalid: {validation.reason}"
            return record

        write = write_field(config, validation, line.line_number)
        if not write.applied:
            record.reason = f"Learned mapping matched but {write.reason}"
            return record

        record.source = SOURCE_LEARNED_MAPPING
        record.final_value = write.final_value
        record.reason = "Recognized by a confirmed learned mapping — AI not consulted"
        return record

    @staticmethod
    def ambiguous_record(line: UnrecognizedLine, matches: list["MappingMatch"]) -> AIFieldMapping:
        """Several learned mappings match with different meanings — never guess."""
        described = "; ".join(
            f"#{m.mapping.id} → {m.mapping.normalized_field}={m.value}" for m in matches
        )
        return AIFieldMapping(
            line_number=line.line_number,
            raw_line=line.raw_line,
            normalized_field="unknown",
            extracted_value=None,
            confidence=0.0,
            confidence_tier=TIER_AMBIGUOUS,
            reasoning=f"Multiple confirmed learned mappings match this line: {described}",
            source=SOURCE_NEEDS_REVIEW,
            status="learned",
            likely_vendor=line.vendor,
            security_concept="unknown",
            reason="Ambiguous learned mappings — not applied",
        )

    @staticmethod
    def rejected_record(line: UnrecognizedLine) -> AIFieldMapping:
        return AIFieldMapping(
            line_number=line.line_number,
            raw_line=line.raw_line,
            normalized_field="unknown",
            extracted_value=None,
            confidence=0.0,
            confidence_tier=ConfidenceTier.LOW.value,
            reasoning="Previously reviewed and rejected by an administrator",
            source=SOURCE_REJECTED,
            status="rejected",
            likely_vendor=line.vendor,
            security_concept="unknown",
            reason="Rejected earlier — not sent to AI again",
        )

    # ── Administrator decisions (Phase 4) ───────────────────────────────────

    def apply_admin(
        self,
        config: NormalizedConfig,
        record: AIFieldMapping,
        normalized_field: str,
        value: str,
        mapping: Optional["LearnedMapping"] = None,
    ) -> AIFieldMapping:
        """Write an administrator-confirmed value; raises ``ValueError`` if invalid."""
        validation = self.validator.validate_value(normalized_field, value)
        if not validation.is_valid:
            raise ValueError(validation.reason)

        write = write_field(config, validation, record.line_number, force=True)
        return dataclasses.replace(
            record,
            normalized_field=normalized_field,
            extracted_value=value,
            confidence=1.0,
            confidence_tier=TIER_CONFIRMED,
            source=SOURCE_ADMIN_CONFIRMED,
            final_value=write.final_value,
            mapping_id=mapping.id if mapping else record.mapping_id,
            security_concept=mapping.concept if mapping else record.security_concept,
            reason="Confirmed by administrator",
        )


# ── Convenience function ──────────────────────────────────────────────────────

def map_interpretations(
    config: NormalizedConfig,
    interpretations: list[InterpretationResult],
    validator: Optional[InterpretationValidator] = None,
) -> list[AIFieldMapping]:
    """
    Apply Phase 3 confidence-based interpretation to *config*.

    This is the single entry point for safe enrichment: interpretations are
    validated, confidence-tiered, and only HIGH-valid results are written to
    config fields.  All results produce an audit entry in
    ``config.ai_mappings``.

    Parameters
    ----------
    config
        The ``NormalizedConfig`` to enrich (modified in-place).
    interpretations
        Phase 2 interpretation results for the config's unrecognized lines.
    validator
        Optional custom validator (defaults to :class:`InterpretationValidator`).

    Returns
    -------
    list[AIFieldMapping]
        One audit record per interpretation, in input order.
    """
    mapper = AdaptiveMapper(validator=validator)
    return mapper.map_interpretations(config, interpretations)
