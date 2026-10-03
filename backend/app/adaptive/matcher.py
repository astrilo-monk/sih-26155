"""
Phase 5 -Command-pattern templates and the learned mapping matcher.

A learned mapping stores *how* a vendor expresses a concept as a safe
template, never as a raw regular expression:

    secure-shell protocol-version {value}
    remote-console protocol telnet
    admin {any} idle-timeout {value}

Template grammar (whitespace-separated tokens):

* literal token   -matched case-insensitively, exactly
* ``{value}``     -captures one token; the extracted value
* ``{any}``       -matches one token (or one quoted string) that is ignored

A statement terminator (``;``) is punctuation, not part of a token: it is dropped
from template tokens and stays optional in the line, so ``server {ip};``,
``server {ip}`` and ``server 192.0.2.1`` all describe the same statement.

Recognizer templates (Phase 6) use typed slots instead of ``{value}``, at most one per template:
``{int}``, ``{ip}``, ``{host}``, ``{duration}`` / ``{duration:<unit>}``, ``{enum:<name>}``,
``{polarity}``, ``{neg}``.

``{host}`` reads an address *or* a hostname / FQDN, so one recognizer covers
``ntp server 192.0.2.10``, ``ntp server 2001:db8::10`` and ``ntp server ntp1.example.com``.

``{rest}`` may only end a recognizer template: it matches whatever options follow (none included), so
``ntp server {host} {rest}`` reads ``ntp server 192.0.2.10 key 1 prefer``. ``validate_recognizer`` decides
which settings may carry one.

``{neg}`` is an *optional* leading negator (``no`` / ``unset`` / ``delete`` / ``undo``) and may only be
the template's first token. It reads the statement's polarity from its own presence, so ``{neg} telnet
server`` is one recognizer for both ``telnet server`` (on) and ``no telnet server`` (off). Leading
negation is what the slot reads, which is why it beats any ``enabled`` / ``on`` word later in the line.

Templates are compiled by escaping every literal, so the resulting regex is
linear and cannot be abused (no user- or AI-supplied regex is ever run).

This module has no database access: ``LearnedMappingMatcher`` receives a
repository object that provides ``list_mappings``.
"""

from __future__ import annotations

import re
from functools import lru_cache
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Protocol

if TYPE_CHECKING:
    from app.db.mappings import LearnedMapping


VALUE_TOKEN = "{value}"
ANY_TOKEN = "{any}"
REST_TOKEN = "{rest}"

EXTRACTION_TEMPLATE_CAPTURE = "template_capture"
EXTRACTION_CONSTANT = "constant"
EXTRACTION_RECOGNIZER = "recognizer"
EXTRACTION_METHODS = frozenset({EXTRACTION_TEMPLATE_CAPTURE, EXTRACTION_CONSTANT, EXTRACTION_RECOGNIZER})

SLOT_PATTERNS = {
    # a version may be written with a version prefix (``v2``); the fact reads it the same way
    "int": r"(?:[Vv]|[Vv]er|[Vv]ersion)?\d+",
    "ip": r"[0-9A-Fa-f.:]+(?:/\d{1,3})?",
    "duration": r"\d+(?:\.\d+)?[A-Za-z]*",
    # an address, or a hostname / FQDN; ``recognizer_value`` decides whether the text is usable
    "host": r"[A-Za-z0-9][\w.:-]*(?:/\d{1,3})?",
    # a storage type may be a number (``secret 0``), a source may be a prefix (``CidrIp 0.0.0.0/0``, ``::/0``)
    "enum": r"[A-Za-z0-9:][\w.+/:-]*",
    "polarity": r"(?:enabled?|disabled?|on|off|true|false|yes|no)",
    # an SNMP community string: read at scan time only, never stored (the template holds the slot)
    "community": r"""(?:"[^"]*"|'[^']*'|\S+)""",
}
_SLOT = re.compile(r"^\{(int|ip|host|duration|enum|polarity|neg|community)(?::([A-Za-z][\w-]*))?\}$")
NEGATION_SLOT = "{neg}"
# An optional leading negator: absent = the statement is in force, present = it is negated.
_NEGATION_PREFIX = r"(?P<slot>(?:no|unset|delete|undo)[\s=]+)?"

# Statement terminators: punctuation in every dialect that uses them, never part of a token
TERMINATORS = ";"

# a Terraform rule (azurerm_network_security_rule) states a dozen keys; the token cap below bounds the regex
MAX_PATTERN_LENGTH = 320
MAX_PATTERN_TOKENS = 32

# A similar-but-not-identical learned pattern is surfaced as a candidate when
# at least this share of its literal words appears in the new line.
SIMILARITY_THRESHOLD = 0.6


class PatternError(ValueError):
    """Raised when a command pattern is not a valid safe template."""


def normalize_line(raw_line: str) -> str:
    """Canonical form used for identity comparisons (whitespace + case)."""
    return " ".join(raw_line.split()).lower()


def strip_terminator(token: str) -> str:
    """A token without its trailing statement terminator (``{ip};`` → ``{ip}``)."""
    stripped = token.rstrip(TERMINATORS)
    return stripped or token


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

    tokens = [strip_terminator(t) for t in pattern.split()]
    if len(tokens) > MAX_PATTERN_TOKENS:
        raise PatternError(f"Command pattern exceeds {MAX_PATTERN_TOKENS} tokens")

    recognizer = extraction_method == EXTRACTION_RECOGNIZER
    slots = [t for t in tokens if recognizer and _SLOT.match(t)]
    if len(slots) > 1:
        raise PatternError("A recognizer template may contain at most one typed slot")
    if NEGATION_SLOT in tokens[1:]:
        raise PatternError(f"{NEGATION_SLOT} reads a leading negator, so it can only be the first token")
    if REST_TOKEN in tokens and (not recognizer or tokens.index(REST_TOKEN) != len(tokens) - 1):
        raise PatternError(f"{REST_TOKEN} can only end a recognizer template")
    literals = [t for t in tokens if t not in (VALUE_TOKEN, ANY_TOKEN, REST_TOKEN) and t not in slots]
    allowed = "typed slots, {any}" if recognizer else f"{VALUE_TOKEN} and {ANY_TOKEN} placeholders"
    for tok in literals:
        if "{" in tok or "}" in tok:
            raise PatternError(f"Invalid token '{tok}': only {allowed} are allowed")
    if not literals:
        raise PatternError("Command pattern must contain at least one literal keyword")

    value_count = tokens.count(VALUE_TOKEN)
    if extraction_method == EXTRACTION_TEMPLATE_CAPTURE and value_count != 1:
        raise PatternError(f"'{EXTRACTION_TEMPLATE_CAPTURE}' patterns need exactly one {VALUE_TOKEN}")
    if extraction_method == EXTRACTION_CONSTANT and value_count != 0:
        raise PatternError(f"'{EXTRACTION_CONSTANT}' patterns must not contain {VALUE_TOKEN}")

    return tokens


# a scan matches every stored template against every line: compiled once per template, not per line
@lru_cache(maxsize=4096)
def compile_pattern(pattern: str, extraction_method: str) -> re.Pattern[str]:
    """Compile a validated template into an anchored, escaped regex."""
    tokens = validate_pattern(pattern, extraction_method)
    # ``{neg}`` is an optional prefix, not a token: it carries its own separator so the rest of the
    # template still has to start the line when no negator is there.
    prefix = _NEGATION_PREFIX if tokens[:1] == [NEGATION_SLOT] else ""
    rest = tokens[-1] == REST_TOKEN
    parts = []
    for tok in (tokens[1:] if prefix else tokens)[:-1 if rest else None]:
        if tok == VALUE_TOKEN:
            parts.append(r"(?P<value>\S+)")
        elif slot := _SLOT.match(tok):
            parts.append(f"(?P<slot>{SLOT_PATTERNS[slot.group(1)]})")
        elif tok == ANY_TOKEN:
            # a quoted string is one value however many words it holds (``message "Authorized only"``)
            parts.append(r"""(?:"[^"]*"|'[^']*'|\S+)""")
        else:
            parts.append(re.escape(tok))
    terminator = f"[{re.escape(TERMINATORS)}]?"
    # ``=`` separates a token from its value in key=value dialects (RouterOS ``disabled=yes``), exactly as
    # the tokenizer splits it; a trailing ``{`` is a block opener, punctuation like the terminator.
    tail = r"(?:[\s=]+.*?)?" if rest else ""
    return re.compile(r"^\s*" + prefix + r"[\s=]+".join(p + terminator for p in parts) + tail + r"(?:\s*\{)?\s*$",
                      re.IGNORECASE)


def match_pattern(pattern: str, extraction_method: str, raw_line: str) -> tuple[bool, Optional[str]]:
    """Return ``(matched, captured_value)`` for a raw configuration line."""
    m = compile_pattern(pattern, extraction_method).match(raw_line)
    if not m:
        return False, None
    if extraction_method == EXTRACTION_TEMPLATE_CAPTURE:
        return True, _strip_quotes(m.group("value"))
    return True, None


@lru_cache(maxsize=4096)
def recognizer_slot(pattern: str) -> tuple[Optional[str], Optional[str]]:
    """``(kind, argument)`` of a recognizer template's typed slot, ``(None, None)`` when it has none."""
    for tok in validate_pattern(pattern, EXTRACTION_RECOGNIZER):
        if slot := _SLOT.match(tok):
            return slot.group(1), slot.group(2)
    return None, None


def match_recognizer(pattern: str, raw_line: str) -> Optional[tuple[Optional[str], Optional[str], Optional[str]]]:
    """``(kind, argument, captured text)`` when the template matches the line, else None."""
    m = compile_pattern(pattern, EXTRACTION_RECOGNIZER).match(raw_line)
    if not m:
        return None
    kind, argument = recognizer_slot(pattern)
    return kind, argument, m.group("slot") if kind else None


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

    Vendor is metadata only -a mapping learned from one vendor applies to
    any config that uses the same syntax. When several mappings match and
    disagree on field or value, the outcome is ``ambiguous`` and nothing is
    guessed.
    """

    def __init__(self, source: MappingSource):
        # Recognizers produce facts (``facts/recognizers.py``), never NormalizedConfig values
        self._mappings = [m for m in source.list_mappings()
                          if m.confirmed and m.active and m.extraction_method != EXTRACTION_RECOGNIZER]

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
