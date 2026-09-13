"""
Phase 6 — AdaptiveService: the single entry point for adaptive enrichment.

    unrecognized security-relevant lines   (Phase 1, captured after parsing)
                 ↓
    previously rejected?      → recorded, never re-sent to the AI
                 ↓
    confirmed learned mapping → reliable match: normalize (no AI call)
                              → ambiguous match: send to review
                 ↓
    AI fallback               → ONE batched interpreter call per config
                 ↓
    AdaptiveMapper            → confidence tiers + validation + safe write
                 ↓
    NormalizedConfig          → existing deterministic compliance engine

Vendor parsers, the AI client and the database stay unaware of each other;
this service is where they meet. Every failure in the adaptive layer
degrades to "unresolved" — it never breaks the deterministic scan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from app.adaptive.interpreter import _make_unavailable_result, interpret_lines
from app.adaptive.mapper import AdaptiveMapper
from app.adaptive.matcher import (
    EXTRACTION_RECOGNIZER,
    MATCH_AMBIGUOUS,
    MATCH_RELIABLE,
    LearnedMappingMatcher,
    MatchOutcome,
    PatternError,
    SimilarMapping,
    match_recognizer,
    normalize_line,
)
from app.ai.client import is_available
from app.ai.interpretation_schemas import InterpretationResult
from app.db.mappings import MappingRepository
from app.models.normalized import AIFieldMapping, NormalizedConfig, UnrecognizedLine

logger = logging.getLogger(__name__)


@dataclass
class AdaptiveOutcome:
    """What the adaptive layer did for one config."""
    # AI results for lines that reached the AI fallback (input order)
    interpretations: list[InterpretationResult] = field(default_factory=list)
    # One audit record per handled line (also appended to config.ai_mappings)
    records: list[AIFieldMapping] = field(default_factory=list)
    # Whether the interpreter was actually called
    ai_called: bool = False
    # Whether AI was enabled and reachable for this config
    ai_available: bool = False
    # Similar learned mappings surfaced as candidates, keyed by line number
    candidates: dict[int, list[SimilarMapping]] = field(default_factory=dict)

    @property
    def learned_matches(self) -> int:
        return sum(1 for r in self.records if r.source == "learned_mapping")


class AdaptiveService:
    def __init__(
        self,
        repository: Optional[MappingRepository] = None,
        interpreter: Optional[Callable[[list[UnrecognizedLine]], list[InterpretationResult]]] = None,
        ai_available: Optional[Callable[[], bool]] = None,
        mapper: Optional[AdaptiveMapper] = None,
    ):
        self.repository = repository or MappingRepository()
        self._interpreter = interpreter or interpret_lines
        self._ai_available = ai_available or is_available
        self.mapper = mapper or AdaptiveMapper()

    def process(
        self,
        config: NormalizedConfig,
        use_ai: bool = True,
        report_unresolved: bool = True,
    ) -> AdaptiveOutcome:
        """
        Enrich *config* in place from its ``unrecognized_lines``.

        ``use_ai`` — allow the AI fallback for lines no learned mapping covers.
        ``report_unresolved`` — create audit records for lines that stay
        unresolved without AI (disabled for known vendors so parser noise does
        not flood the review queue).
        """
        outcome = AdaptiveOutcome()
        outcome.ai_available = bool(use_ai and self._safe_ai_available())

        matcher, rejected_keys, recognizers = self._load_knowledge()
        records: dict[int, AIFieldMapping] = {}
        unresolved: list[UnrecognizedLine] = []

        for line in config.unrecognized_lines:
            if normalize_line(line.raw_line) in rejected_keys:
                records[line.line_number] = self.mapper.rejected_record(line)
                continue
            if self._recognized(line.raw_line, recognizers):
                continue  # answered by a confirmed recognizer (facts/recognizers.py): no AI, no review

            match = matcher.match_line(line.raw_line) if matcher else MatchOutcome(status="none")
            if match.candidates:
                outcome.candidates[line.line_number] = match.candidates

            if match.status == MATCH_RELIABLE:
                records[line.line_number] = self.mapper.apply_learned(config, line, match.match)
            elif match.status == MATCH_AMBIGUOUS:
                records[line.line_number] = self.mapper.ambiguous_record(line, match.matches)
            else:
                unresolved.append(line)

        if unresolved and (outcome.ai_available or report_unresolved):
            outcome.interpretations = self._interpret(unresolved, outcome)
            for interp in outcome.interpretations:
                similar = outcome.candidates.get(interp.line_number, [])
                # an AI interpretation is a proposal: reviewed, never written to the config without an admin
                records[interp.line_number] = self.mapper.process_interpretation(
                    config, interp,
                    learned_candidate_fields={c.mapping.normalized_field for c in similar},
                    auto_apply=False,
                )

        outcome.records = [records[n] for n in sorted(records)]
        config.ai_mappings.extend(outcome.records)

        logger.info(
            "Adaptive: %d lines → %d learned, %d via AI (called=%s), %d unresolved",
            len(config.unrecognized_lines), outcome.learned_matches,
            len(outcome.interpretations), outcome.ai_called,
            sum(1 for r in outcome.records if not r.applied),
        )
        return outcome

    # ── helpers ─────────────────────────────────────────────────────────────

    def _safe_ai_available(self) -> bool:
        try:
            return bool(self._ai_available())
        except Exception as e:
            logger.warning("AI availability check failed: %s", e)
            return False

    def _load_knowledge(self) -> tuple[Optional[LearnedMappingMatcher], set[str], list]:
        """Load learned mappings once per config; a DB failure means 'no knowledge'."""
        try:
            recognizers = [m for m in self.repository.list_mappings()
                           if m.confirmed and m.extraction_method == EXTRACTION_RECOGNIZER]
            return LearnedMappingMatcher(self.repository), self.repository.rejected_line_keys(), recognizers
        except Exception as e:
            logger.warning("Learned mapping store unavailable — continuing without it: %s", e)
            return None, set(), []

    @staticmethod
    def _recognized(raw_line: str, recognizers: list) -> bool:
        for recognizer in recognizers:
            try:
                if match_recognizer(recognizer.command_pattern, raw_line):
                    return True
            except PatternError:
                continue
        return False

    def _interpret(self, lines: list[UnrecognizedLine], outcome: AdaptiveOutcome) -> list[InterpretationResult]:
        if not outcome.ai_available:
            reason = "AI interpretation unavailable — AI is disabled or not configured for this scan"
            return [_make_unavailable_result(ln, reason) for ln in lines]

        outcome.ai_called = True
        try:
            results = self._interpreter(lines) or []
        except Exception as e:
            logger.warning("Adaptive interpreter failed: %s", e)
            return [_make_unavailable_result(ln) for ln in lines]

        wanted = {ln.line_number for ln in lines}
        return [r for r in results if r.line_number in wanted]
