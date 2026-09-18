"""
Recognizers: admin-confirmed templates that answer a security predicate decisively.

    scan → provisional (heuristic) result → admin confirms a line → recognizer saved
         → next scan: the recognizer answers that syntax with a CONFIRMED fact — no heuristic, no AI

A recognizer is a learned mapping with extraction method ``recognizer``:

* ``command_pattern`` — typed-slot template, e.g. ``remote-console protocol {enum:protocol}``
* ``predicate`` / ``subject`` — the fact it produces
* ``scope_template`` — optional: some enclosing block header must match it
* ``dialect_fingerprint`` — top-level keywords of the config it was confirmed on; it only
  applies to configs sharing enough of them (empty = any dialect)
* ``negatives`` — lines it must never match
* ``constant_value`` — JSON: the value of a slot-less template, or an ``{enum:…}`` value table
  (``{"telnet": true, "*": false}``)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Iterable, Optional

from app.adaptive.matcher import (
    EXTRACTION_RECOGNIZER, PatternError, compile_pattern, match_recognizer, normalize_line, recognizer_slot,
    strip_terminator,
)
from app.facts import lexicon as L
from app.facts.heuristics import _Candidate, _polarity, _version, combine, heuristic_candidates, state_lines
from app.facts.predicates import (
    CENTRAL_AAA, DISCOVERY_PROTOCOL, IDLE_TIMEOUT, LOG_REMOTE_DESTINATION, LOGIN_BANNER, NTP_AUTHENTICATED,
    NTP_SERVER, PASSWORD_ENCRYPTION_SERVICE, PASSWORD_STORAGE, PERMIT_ANY, PROTOCOL_ENABLED, SOURCE_RESTRICTED,
    SOURCE_ROUTING, SSH_VERSION, SecurityFact,
)
from app.models.results import Assurance
from app.structure.tokenizer import IP, NEGATIVE, NEGATORS, POSITIVE, Statement, tokenize, tokenize_line

logger = logging.getLogger(__name__)

BOOL_PREDICATES = frozenset({
    PROTOCOL_ENABLED, SOURCE_RESTRICTED, CENTRAL_AAA, NTP_AUTHENTICATED, LOGIN_BANNER, SOURCE_ROUTING,
    DISCOVERY_PROTOCOL, PERMIT_ANY, PASSWORD_ENCRYPTION_SERVICE,
})
# The slot a value predicate is read from
SLOT_PREDICATES = {
    SSH_VERSION: "int", IDLE_TIMEOUT: "duration", LOG_REMOTE_DESTINATION: "ip", NTP_SERVER: "ip",
    PASSWORD_STORAGE: "enum",
}
RECOGNIZER_PREDICATES = BOOL_PREDICATES | frozenset(SLOT_PREDICATES)
STOPWORDS = POSITIVE | NEGATIVE | NEGATORS | {"set", "config", "edit", "next", "end", "exit", "state", "status"}
# A recognizer must be this specific. A hierarchical dialect keeps the nouns in the block header
# (``ntp { server 1.2.3.4; }``), so the scope template counts too — but never on its own: the
# statement itself must still carry a keyword, or the recognizer would answer any line in the block.
MIN_KEYWORDS = 2
FINGERPRINT_OVERLAP = 0.5
_DURATION = re.compile(r"^(\d+(?:\.\d+)?)([a-z]*)$")
_WORD = re.compile(r"^[a-z][\w.+-]*$")


class RecognizerError(ValueError):
    """A recognizer failed a safety gate."""


def _keywords(pattern: str) -> list[str]:
    """Literal words of a template: no slots, no punctuation, no stopwords."""
    return [t for t in map(strip_terminator, pattern.split()) if "{" not in t and t.lower() not in STOPWORDS]


# ── values ──────────────────────────────────────────────────────────────────

def recognizer_value(recognizer, slot: tuple) -> Any:
    """Fact value for a template match; None when the line gives no usable value."""
    kind, argument, text = slot
    constant = json.loads(recognizer.constant_value) if recognizer.constant_value else None
    if kind is None:
        return constant
    word = text.strip("\"'").lower()
    if kind == "polarity":
        return word in POSITIVE
    if kind == "enum":
        return constant.get(word, constant.get("*")) if isinstance(constant, dict) else word
    if kind == "int":
        number = _version(word)
        return None if number is None else int(number)
    if kind == "ip":
        return [word] if IP.match(word) else None
    number, unit = _DURATION.match(word).groups()
    unit = unit or (argument or "").lower()
    factor = 1 if unit in L.MINUTES else 1 / 60 if unit in L.SECONDS else 60 if unit in L.HOURS else None
    return float(number) * factor if factor else None


def validate_recognizer(r) -> None:
    """Safety gates. Raises ``RecognizerError``."""
    if r.predicate not in RECOGNIZER_PREDICATES:
        raise RecognizerError(f"Recognizers cannot answer '{r.predicate}' yet")
    try:
        kind, argument = recognizer_slot(r.command_pattern)
        if r.scope_template:
            compile_pattern(r.scope_template, EXTRACTION_RECOGNIZER)
    except PatternError as e:
        raise RecognizerError(str(e)) from e

    keywords = _keywords(r.command_pattern)
    scoped = keywords + _keywords(r.scope_template or "")
    if not keywords or len(scoped) < MIN_KEYWORDS:
        raise RecognizerError(f"The template needs at least {MIN_KEYWORDS} keywords besides stopwords, counting "
                              f"its scope (found: {', '.join(scoped) or 'none'})")
    try:
        constant = json.loads(r.constant_value) if r.constant_value else None
    except ValueError as e:
        raise RecognizerError("The value must be JSON (true, false, a number, or an enum table)") from e

    slot = match_recognizer(r.command_pattern, r.example_line or "")
    if slot is None:
        raise RecognizerError("The template does not match its example line")
    if kind == "duration" and not argument and not _DURATION.match(slot[2].lower()).group(2):
        raise RecognizerError("The line states no unit: pick one with {duration:min}, {duration:s} or {duration:h}")
    value = recognizer_value(r, slot)

    if r.predicate in BOOL_PREDICATES:
        if kind is None:
            statement = tokenize_line(r.example_line)
            polarity = statement.polarity if statement else None
            if polarity is None and not _declares_presence(r, statement, value):
                raise RecognizerError("Polarity must be stated: a literal such as 'disabled', a {polarity} slot, "
                                      "an {enum:name} slot with a true / false value table, or a scoped bare "
                                      "statement that switches its feature on by existing")
            if polarity is not None and value is not polarity:
                raise RecognizerError(f"The value {json.dumps(value)} contradicts the line, which says "
                                      f"{'enabled' if polarity else 'disabled'}")
        elif kind == "enum":
            if not (isinstance(constant, dict) and constant and all(isinstance(v, bool) for v in constant.values())):
                raise RecognizerError('An {enum:name} slot needs a true / false value table, '
                                      'e.g. {"telnet": true, "*": false}')
        elif kind != "polarity":
            raise RecognizerError(f"A {{{kind}}} slot cannot say whether a setting is on or off")
        if not isinstance(value, bool):
            raise RecognizerError("The example line gives no true / false value")
    else:
        expected = SLOT_PREDICATES[r.predicate]
        if kind != expected:
            raise RecognizerError(f"This setting is read from an {{{expected}}} slot")
        if value is None:
            raise RecognizerError("The example line gives no usable value")


def _declares_presence(r, statement, value) -> bool:
    """A bare statement inside a named block switches its feature on by existing (``services { telnet; }``).

    Only ever True, only with a scope: without one the template would answer the same word anywhere in
    the configuration. Absence of the line still matches nothing, so it can never produce a value."""
    return (bool(r.scope_template) and value is True and statement is not None
            and len(statement.key_tokens) == 1 and not statement.values)


# ── matching ────────────────────────────────────────────────────────────────

def dialect_fingerprint(raw_lines: list[str]) -> str:
    return _fingerprint(tokenize(raw_lines))


def _fingerprint(statements: list[Statement]) -> str:
    """Leading keywords of top-level statements (a flat block counts once)."""
    return " ".join(sorted({s.key_tokens[0] for s in statements if s.scope_path in ((), (s.key_tokens[0],))}))


def _dialect_matches(stored: Optional[str], current: set[str]) -> bool:
    words = set((stored or "").split())
    return not words or len(words & current) >= FINGERPRINT_OVERLAP * min(len(words), len(current))


def recognizer_facts(raw_lines: list[str], extra: Iterable = ()) -> tuple[list[SecurityFact], frozenset[int]]:
    """CONFIRMED facts from stored (+ ``extra``) recognizers, and the lines heuristics must skip:
    lines a recognizer answered or an administrator rejected."""
    recognizers, rejected = _stored_knowledge()
    statements = tokenize(raw_lines)
    current = set(_fingerprint(statements).split())
    candidates, recognized = [], set()

    for s in statements:
        for r in [*recognizers, *extra]:
            try:
                if (normalize_line(s.text) in r.negatives or not _dialect_matches(r.dialect_fingerprint, current)
                        or r.scope_template and not any(compile_pattern(r.scope_template, EXTRACTION_RECOGNIZER)
                                                        .match(h) for h in s.scope_path)
                        or (slot := match_recognizer(r.command_pattern, s.text)) is None):
                    continue
                value = recognizer_value(r, slot)
            except (PatternError, ValueError, AttributeError) as e:
                logger.warning("Recognizer #%s skipped: %s", getattr(r, "id", None), e)
                continue
            polarity, lines = _polarity(s, statements)
            if s.polarity is None and polarity is False:
                # a disabled block switches its settings off; its values configure nothing
                if r.predicate not in BOOL_PREDICATES:
                    continue
                value = False
            if value is None:
                continue
            recognized.add(s.line)
            candidates.append(_Candidate(r.predicate, value, lines or [s.line], subject=r.subject,
                                         unit="min" if r.predicate == IDLE_TIMEOUT else None))

    from app.db.mappings import rejection_key  # the store imports this module for its gates

    skip = recognized | {n for n, text in enumerate(raw_lines, 1) if text.strip() and rejection_key(text) in rejected}
    return combine(candidates, raw_lines, Assurance.CONFIRMED), frozenset(skip)


def _stored_knowledge() -> tuple[list, set[str]]:
    """Active confirmed recognizers and rejected line keys; a store failure means no knowledge."""
    try:
        from app.db.mappings import MappingRepository  # the store imports this module for its gates

        repository = MappingRepository()
        recognizers = [m for m in repository.list_mappings()
                       if m.confirmed and m.extraction_method == EXTRACTION_RECOGNIZER]
        return recognizers, repository.rejected_line_keys()
    except Exception as e:
        logger.warning("Recognizer store unavailable — continuing without it: %s", e)
        return [], set()


# ── review queue and drafting ───────────────────────────────────────────────

def provisional_lines(raw_lines: list[str], needs: Iterable[str],
                      extra: Iterable[_Candidate] = ()) -> list[tuple[int, _Candidate]]:
    """Heuristic statements (and ``extra``: verified AI judge proposals) an administrator can confirm, by line."""
    _, skip = recognizer_facts(raw_lines)
    statements = tokenize(raw_lines)
    found: dict[int, _Candidate] = {}
    for c in [*heuristic_candidates(raw_lines, skip), *extra]:
        if c.predicate in needs and c.predicate in RECOGNIZER_PREDICATES:
            for n in set(c.lines) - state_lines(c, statements) - skip:
                found.setdefault(n, c)
    return sorted(found.items(), key=lambda item: item[0])


def draft_recognizer(raw_lines: list[str], needs: Iterable[str], line_number: int,
                     extra: Iterable[_Candidate] = (), asserted: Optional[_Candidate] = None) -> dict:
    """Recognizer fields drafted from a line (the admin reviews them before saving).

    The line is one a heuristic or a verified AI proposal read, or — ``asserted`` — any line of the
    configuration whose meaning an administrator stated. Either way the draft is only a proposal:
    ``validate_recognizer`` still has to find that meaning on the line itself.
    """
    candidate = asserted or dict(provisional_lines(raw_lines, needs, extra)).get(line_number)
    if candidate is None:
        raise LookupError(f"Line {line_number} holds no provisional statement for this control")
    statement = next(s for s in tokenize(raw_lines) if s.line == line_number)
    template, value = _draft_template(statement, candidate)
    return dict(
        command_pattern=template,
        constant_value=None if value is None else json.dumps(value),
        predicate=candidate.predicate,
        subject=candidate.subject,
        scope_template=_draft_scope(statement),
        dialect_fingerprint=dialect_fingerprint(raw_lines),
        example_line=statement.text.strip(),
    )


def _draft_template(s: Statement, c: _Candidate) -> tuple[str, Any]:
    # Template tokens are the statement's words: block punctuation and statement terminators are not part
    # of any token, so a drafted value slot lines up with the value the candidate was read from.
    tokens = [t for t in map(strip_terminator, s.text.split()) if t not in ("{", "}")]
    words = [t.strip("\"'").lower() for t in tokens]

    def slot(index: int, kind: str) -> str:
        name = words[index - 1] if index and _WORD.match(words[index - 1]) else "value"
        return " ".join([*tokens[:index], f"{{enum:{name}}}" if kind == "enum" else f"{{{kind}}}", *tokens[index + 1:]])

    if c.predicate in BOOL_PREDICATES:
        polar = [i for i, w in enumerate(words) if w in POSITIVE | NEGATIVE and not (i == 0 and w in NEGATORS)]
        if polar and (words[polar[-1]] in POSITIVE) == c.value:
            return slot(polar[-1], "polarity"), None
        names = L.MGMT_PROTOCOLS.get(c.subject, {c.subject}) if c.subject else set()
        # a one-word statement is the feature itself, not a selector: it stays literal, scoped by its block
        if len(words) > 1 and (index := next((i for i, w in enumerate(words) if w in names), None)) is not None:
            # a selector: naming another protocol means this one is off
            return slot(index, "enum"), {words[index]: c.value, "*": not c.value}
        if len(words) > 1 and _WORD.match(words[-1]):
            return slot(len(words) - 1, "enum"), {words[-1]: c.value}
        return " ".join(tokens), c.value

    kind = SLOT_PREDICATES[c.predicate]
    # what counts as a value here is what the fact was read from, so the slot lands on the same token
    wanted = {"int": _version, "ip": IP.match, "duration": _DURATION.match, "enum": _WORD.match}[kind]
    index = next((i for i in reversed(range(1, len(words))) if wanted(words[i]) is not None), None)
    if index is None:
        return " ".join(tokens), c.value
    # a duration whose line states no unit carries the unit the fact was read with, so the draft validates
    if kind == "duration" and c.unit and not _DURATION.match(words[index]).group(2):
        return " ".join([*tokens[:index], f"{{duration:{c.unit}}}", *tokens[index + 1:]]), None
    return slot(index, kind), None


def _draft_scope(s: Statement) -> Optional[str]:
    """The innermost enclosing block header (not a flat prefix), with its arguments as ``{any}``."""
    headers = s.scope_path[:-1] if s.block else s.scope_path
    if not headers:
        return None
    tokens = [t for t in headers[-1].split() if "{" not in t and "}" not in t]
    return " ".join(t if _WORD.match(t.lower()) else "{any}" for t in tokens) or None
