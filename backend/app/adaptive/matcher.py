"""
Phase 5 — Command-pattern templates and the learned mapping matcher.

A learned mapping stores *how* a vendor expresses a concept as a safe
template, never as a raw regular expression:

    secure-shell protocol-version {value}
    remote-console protocol telnet
    admin {any} idle-timeout {value}

Template grammar (whitespace-separated tokens):

* literal token   — matched case-insensitively, exactly
* ``{value}``     — captures one token; the extracted value
* ``{any}``       — matches one token that is ignored

Templates are compiled by escaping every literal, so the resulting regex is
linear and cannot be abused (no user- or AI-supplied regex is ever run).

This module has no database access: ``LearnedMappingMatcher`` receives a
repository object that provides ``list_mappings``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Protocol

if TYPE_CHECKING:
    from app.db.mappings import LearnedMapping


VALUE_TOKEN = "{value}"
ANY_TOKEN = "{any}"

EXTRACTION_TEMPLATE_CAPTURE = "template_capture"
EXTRACTION_CONSTANT = "constant"
EXTRACTION_METHODS = frozenset({EXTRACTION_TEMPLATE_CAPTURE, EXTRACTION_CONSTANT})

MAX_PATTERN_LENGTH = 256
MAX_PATTERN_TOKENS = 32

# A similar-but-not-identical learned pattern is surfaced as a candidate when
# at least this share of its literal words appears in the new line.
SIMILARITY_THRESHOLD = 0.6


class PatternError(ValueError):
    """Raised when a command pattern is not a valid safe template."""


def normalize_line(raw_line: str) -> str:
    """Canonical form used for identity comparisons (whitespace + case)."""
    return " ".join(raw_line.split()).lower()


def _strip_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def validate_pattern(pattern: str, extraction_method: str) -> list[str]:
    """Validate a template and return its tokens. Raises ``PatternError``."""
    if extraction_method not in EXTRACTION_METHODS:
        raise PatternError(f"Unsupported extraction method '{extraction_method}'")
    if not pattern or not pattern.strip():
        raise PatternError("Command pattern is empty")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise PatternError(f"Command pattern exceeds {MAX_PATTERN_LENGTH} characters")

    tokens = pattern.split()
    if len(tokens) > MAX_PATTERN_TOKENS:
        raise PatternError(f"Command pattern exceeds {MAX_PATTERN_TOKENS} tokens")

    literals = [t for t in tokens if t not in (VALUE_TOKEN, ANY_TOKEN)]
    for tok in literals:
        if "{" in tok or "}" in tok:
            raise PatternError(
                f"Invalid token '{tok}': only {VALUE_TOKEN} and {ANY_TOKEN} placeholders are allowed"
            )
    if not literals:
        raise PatternError("Command pattern must contain at least one literal keyword")

    value_count = tokens.count(VALUE_TOKEN)
    if extraction_method == EXTRACTION_TEMPLATE_CAPTURE and value_count != 1:
        raise PatternError(f"'{EXTRACTION_TEMPLATE_CAPTURE}' patterns need exactly one {VALUE_TOKEN}")
    if extraction_method == EXTRACTION_CONSTANT and value_count != 0:
        raise PatternError(f"'{EXTRACTION_CONSTANT}' patterns must not contain {VALUE_TOKEN}")

    return tokens


def compile_pattern(pattern: str, extraction_method: str) -> re.Pattern[str]:
    """Compile a validated template into an anchored, escaped regex."""
    parts = []
    for tok in validate_pattern(pattern, extraction_method):
        if tok == VALUE_TOKEN:
            parts.append(r"(?P<value>\S+)")
        elif tok == ANY_TOKEN:
            parts.append(r"\S+")
        else:
            parts.append(re.escape(tok))
    return re.compile(r"^\s*" + r"\s+".join(parts) + r"\s*$", re.IGNORECASE)


def match_pattern(pattern: str, extraction_method: str, raw_line: str) -> tuple[bool, Optional[str]]:
    """Return ``(matched, captured_value)`` for a raw configuration line."""
    m = compile_pattern(pattern, extraction_method).match(raw_line)
    if not m:
        return False, None
    if extraction_method == EXTRACTION_TEMPLATE_CAPTURE:
        return True, _strip_quotes(m.group("value"))
    return True, None


def derive_pattern(raw_line: str, extracted_value: Optional[str]) -> tuple[str, str]:
    """
    Build a template from an admin-confirmed line.

    If the confirmed value appears exactly once as a token, that token becomes
    ``{value}`` so the same syntax with a different value is recognized later.
    Otherwise the whole line is stored literally with a constant value.
    """
    tokens = raw_line.split()
    if extracted_value is not None:
        target = extracted_value.strip().lower()
        hits = [i for i, t in enumerate(tokens) if _strip_quotes(t).lower() == target]
        if len(hits) == 1 and len(tokens) > 1:
            tokens[hits[0]] = VALUE_TOKEN
            return " ".join(tokens), EXTRACTION_TEMPLATE_CAPTURE
    return " ".join(tokens), EXTRACTION_CONSTANT


def _words(text: str) -> set[str]:
    """Lowercase keyword set, splitting hyphenated tokens and dropping numbers."""
    words = set()
    for tok in text.lower().split():
        if tok in (VALUE_TOKEN, ANY_TOKEN):
            continue
        for part in re.split(r"[-_./:]", _strip_quotes(tok)):
            if part and not part.isdigit():
                words.add(part)
    return words


def pattern_similarity(pattern: str, raw_line: str) -> float:
    """Share of the pattern's literal words that also occur in the line."""
    pattern_words = _words(pattern)
    if not pattern_words:
        return 0.0
    return len(pattern_words & _words(raw_line)) / len(pattern_words)


# ── Matcher ───────────────────────────────────────────────────────────────────

class MappingSource(Protocol):
    def list_mappings(self, include_inactive: bool = False) -> list["LearnedMapping"]: ...


@dataclass
class MappingMatch:
    """A confirmed mapping whose template matched the line exactly."""
    mapping: "LearnedMapping"
    value: Optional[str]


@dataclass
class SimilarMapping:
    """A confirmed mapping that resembles the line but did not match exactly."""
    mapping: "LearnedMapping"
    score: float


MATCH_NONE = "none"
MATCH_RELIABLE = "matched"
MATCH_AMBIGUOUS = "ambiguous"


@dataclass
class MatchOutcome:
    status: str
    matches: list[MappingMatch] = field(default_factory=list)
    candidates: list[SimilarMapping] = field(default_factory=list)

    @property
    def match(self) -> Optional[MappingMatch]:
        return self.matches[0] if self.status == MATCH_RELIABLE else None


class LearnedMappingMatcher:
    """
    Checks unrecognized lines against confirmed, active learned mappings.

    Vendor is metadata only — a mapping learned from one vendor applies to
    any config that uses the same syntax. When several mappings match and
    disagree on field or value, the outcome is ``ambiguous`` and nothing is
    guessed.
    """

    def __init__(self, source: MappingSource):
        self._mappings = [m for m in source.list_mappings() if m.confirmed and m.active]

    def match_line(self, raw_line: str, max_candidates: int = 3) -> MatchOutcome:
        matches: list[MappingMatch] = []
        similar: list[SimilarMapping] = []

        for mapping in self._mappings:
            try:
                matched, captured = match_pattern(
                    mapping.command_pattern, mapping.extraction_method, raw_line
                )
            except PatternError:
                continue  # stored pattern became invalid; never guess with it

            if matched:
                value = captured if mapping.extraction_method == EXTRACTION_TEMPLATE_CAPTURE else mapping.constant_value
                matches.append(MappingMatch(mapping=mapping, value=value))
                continue

            score = pattern_similarity(mapping.command_pattern, raw_line)
            if score >= SIMILARITY_THRESHOLD:
                similar.append(SimilarMapping(mapping=mapping, score=round(score, 2)))

        similar.sort(key=lambda s: s.score, reverse=True)
        candidates = similar[:max_candidates]

        if not matches:
            return MatchOutcome(status=MATCH_NONE, candidates=candidates)

        interpretations = {
            (m.mapping.normalized_field, (m.value or "").strip().lower()) for m in matches
        }
        status = MATCH_RELIABLE if len(interpretations) == 1 else MATCH_AMBIGUOUS
        return MatchOutcome(status=status, matches=matches, candidates=candidates)
