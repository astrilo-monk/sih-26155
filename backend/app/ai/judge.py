"""
Phase 7 -AI escalation: the AI judges only the controls the deterministic pipeline left UNKNOWN.

    UNKNOWN control with lines about one of its settings -lines the lexicon reads, or unfamiliar lines
    naming related vocabulary (``operator lock-after 10 minutes``); without such evidence, at most
    MAX_RELATED related lines of the config
        → those lines' tokenizer scopes (their blocks, capped, plus enclosing headers), redacted and scrubbed
        → one request per CONTROLS_PER_CALL controls, most severe first, until the scan budget is spent
        → SQLite cache keyed by hash(prompt version + model + system prompt + prompt); only answers that
          verified are stored, and a cached answer is re-verified (nothing verifies → asked again)
        → fact proposals citing line refs → deterministic verifier → AI_VERIFIED facts bound to the asking
          control (the evaluator reports them as UNKNOWN with a proposed status: never scored)

The verifier discards a proposal unless the control was asked, the predicate is one it needs, the quoted
evidence occurs on a cited line, all cited lines sit in one tokenizer scope (block state lines included) and
every cited setting line supports the value: a line the lexicon reads must be read the same way; an
unfamiliar line must name related vocabulary for the setting (never limits, counters or lockouts) and itself
state the value -its polarity or its block's, a number with its written unit, an address. Absence cannot be
cited, so the AI can never pass a control from absence.

NOT_CONFIGURED controls take the same path as evidence discovery: the lexicon found nothing, so only related
lines (at most MAX_RELATED) are sent, marked ``discover``, after every UNKNOWN control. A verified discovery is a
provisional fact like any other (the control reports UNKNOWN); no verified citation leaves NOT_CONFIGURED as it was.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from app.adaptive.context import _header, structural_paths
from app.ai.client import ERROR_REQUEST_FAILED, StructuredResponse, request_structured
from app.ai.redaction import Redactor
from app.analysis.scoring import WEIGHTS
from app.controls.catalog import CONTROLS, Control
from app.db.database import get_connection
from app.facts import lexicon as L
from app.facts.heuristics import (
    _NUMBER, _Candidate, _context, _parts, _polarity, combine, heuristic_candidates, state_lines,
)
from app.facts.predicates import (
    CENTRAL_AAA, DISCOVERY_PROTOCOL, IDLE_TIMEOUT, LOG_REMOTE_DESTINATION, LOGIN_BANNER, NTP_AUTHENTICATED,
    NTP_SERVER, PROTOCOL_ENABLED, SOURCE_RESTRICTED, SSH_VERSION,
)
from app.facts.recognizers import BOOL_PREDICATES
from app.models.normalized import NormalizedConfig
from app.models.results import Assurance, ControlResult, Status
from app.structure.tokenizer import IP, NUMBER, Statement, tokenize
from app.ai.fence import DATA_RULE, fence

logger = logging.getLogger(__name__)

MODEL = "openai/gpt-oss-120b"
# Bump when the verifier or the response contract changes: old cache entries stop matching
PROMPT_VERSION = "judge-v4"
CONTROLS_PER_CALL = 4
MAX_BLOCK_LINES = 15
# Related lines sent for a control whose own evidence names none of its settings
MAX_RELATED = 3

_VALUE_FORMATS = {
    SSH_VERSION: "integer",
    IDLE_TIMEOUT: "number; unit min, s or h exactly as written on the cited line",
    LOG_REMOTE_DESTINATION: "one IP address or DNS hostname",
    NTP_SERVER: "one IP address or DNS hostname",
}
AI_PREDICATES = BOOL_PREDICATES | frozenset(_VALUE_FORMATS)
# Controls that read one subject of a shared predicate
_SUBJECTS = {"MGMT-001": "telnet", "MGMT-002": "http"}
_UNITS = {"min": 1.0, "s": 1 / 60, "h": 60.0}
_UNIT_WORDS = {"min": L.MINUTES, "s": L.SECONDS, "h": L.HOURS}
# A dotted DNS name with a letter: `0.pool.ntp.org` (IPs and numbers such as `1.5min` are excluded by the caller)
HOSTNAME = re.compile(r"^(?=.*[a-z])[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")
# Vocabulary an unfamiliar line needs before its value is read (subject predicates are checked by name)
_RELATED = {
    SOURCE_RESTRICTED: L.SOURCE_RELATED, IDLE_TIMEOUT: L.IDLE_RELATED, LOG_REMOTE_DESTINATION: L.LOG_RELATED,
    NTP_SERVER: L.TIME_RELATED, CENTRAL_AAA: L.AAA_RELATED, LOGIN_BANNER: L.BANNER_RELATED,
}

SYSTEM_PROMPT = """You are the evidence reader of a vendor-agnostic network security auditor.
You receive security questions a deterministic engine could not answer and an excerpt of one device
configuration (any vendor, possibly unfamiliar syntax). Propose only facts that excerpt lines state explicitly.

RULES
1. line_refs: the excerpt line [n] that states the fact, plus its block's on/off state line if needed.
   Never cite a line that does not state the fact. Never combine lines from different blocks.
2. Unfamiliar keywords are fine when their meaning is the asked setting (e.g. an automatic lock after
   inactivity is an idle timeout). Limits, counters, retries and lockouts after failures are not.
3. Never infer from absence, vendor defaults or best practice. Not stated -> no proposal.
   A question marked "discover" found no setting: propose only a line that explicitly states it.
4. evidence: the exact words of a cited line that state the value. Secrets appear as <SECRET:...>.
5. value: "true" or "false" (the resulting state) for true/false facts; digits for numbers
   (unit "min", "s" or "h" only when the line writes a unit, else null); one IP address or hostname per proposal.
6. subject: the protocol for protocol facts (telnet, http, cdp, lldp), otherwise null.
7. Uncertain -> no proposal. An empty list is a valid answer. You never decide compliance.
"""
SYSTEM_PROMPT += DATA_RULE

_PROPOSAL = {
    "control_id": {"type": "string"},
    "predicate": {"type": "string"},
    "subject": {"type": ["string", "null"]},
    "value": {"type": "string"},
    "unit": {"type": ["string", "null"]},
    "line_refs": {"type": "array", "items": {"type": "integer"}},
    "evidence": {"type": "string"},
    "reasoning": {"type": "string"},
}
RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "judge_response",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {"proposals": {"type": "array", "items": {
                "type": "object", "properties": _PROPOSAL, "required": list(_PROPOSAL), "additionalProperties": False,
            }}},
            "required": ["proposals"],
            "additionalProperties": False,
        },
    },
}


@dataclass
class Budget:
    """AI calls left for one scan, and what was spent (cache hits are free)."""
    remaining: int
    calls: int = 0
    cache_hits: int = 0


def judge_config(config: NormalizedConfig, results: list[ControlResult], budget: Budget) -> None:
    """Escalate the eligible UNKNOWN controls of an unknown-vendor config, then discover NOT_CONFIGURED ones.

    Sets ``config.ai_facts`` (verified proposals, each bound to its control) and ``config.ai_notes``
    (why a control stayed unjudged).
    """
    raw = config.raw_lines
    statements = tokenize(raw)
    by_line = {s.line: s for s in statements}
    readings = _readings(raw, statements)
    eligible = [r for r in results if r.status in (Status.UNKNOWN, Status.NOT_CONFIGURED)]
    lines_of = {r.control_id: lines for r in eligible
                if (lines := _target_lines(CONTROLS[r.control_id], r.evidence.line_numbers, statements, readings))}
    # NOT_CONFIGURED cites nothing: its target lines are related lines only, and it never displaces an UNKNOWN control
    discover = {r.control_id for r in eligible if r.status == Status.NOT_CONFIGURED}
    targets = sorted(lines_of, key=lambda cid: (cid in discover, -WEIGHTS[CONTROLS[cid].severity], cid))
    if not targets:
        return
    # Redact the whole configuration first so every secret is known, then scrub each excerpt as a whole:
    # a value redacted on one line is also removed where another line repeats it
    redactor, paths = Redactor(), structural_paths(raw)
    redacted = [redactor.line(text.rstrip(), paths[i]) for i, text in enumerate(raw)]
    found: list[tuple[str, _Candidate]] = []

    for start in range(0, len(targets), CONTROLS_PER_CALL):
        controls = [CONTROLS[cid] for cid in targets[start:start + CONTROLS_PER_CALL]]
        numbers = sorted({n for c in controls for cited in lines_of[c.control_id]
                          for n in _excerpt(raw, paths, statements, by_line[cited])})
        shown = {n: line for n, line in zip(numbers, redactor.scrub("\n".join(redacted[n - 1] for n in numbers))
                                            .split("\n"))}
        scopes = {c.control_id: [by_line[n] for n in lines_of[c.control_id]] for c in controls}
        prompt = redactor.scrub(_prompt(controls, scopes, numbers, shown, discover))

        def verified(proposals) -> list[tuple[str, _Candidate]]:
            return [(p["control_id"], c) for p in proposals or ()
                    if (c := verify(p, controls, numbers, shown, by_line, readings, statements)) is not None]

        key = hashlib.sha256(f"{PROMPT_VERSION}\n{MODEL}\n{SYSTEM_PROMPT}\n{prompt}".encode()).hexdigest()
        accepted = verified(_cache_get(key))
        if accepted:
            budget.cache_hits += 1
        else:
            proposals = _request(prompt, budget, config, controls)
            if proposals is None:
                continue
            accepted = verified(proposals)
            if accepted:  # an answer with nothing verifiable is never cached: the next scan asks again
                _cache_put(key, proposals)
        for control in controls:
            if not any(control_id == control.control_id for control_id, _ in accepted):
                config.ai_notes[control.control_id] = "the AI proposed no fact with a verifiable citation"
        found += accepted

    config.ai_facts = []
    for control_id in dict.fromkeys(control_id for control_id, _ in found):
        facts = combine([c for cid, c in found if cid == control_id], raw, Assurance.AI_VERIFIED)
        for fact in facts:
            fact.control_id = control_id
        config.ai_facts += facts


# ── lexicon readings, related lines, eligibility, excerpt ───────────────────

def _readings(raw: list[str], statements: list[Statement]) -> dict[int, list[_Candidate]]:
    """Lexicon candidates by the setting lines they are stated on (block state lines excluded)."""
    readings: dict[int, list[_Candidate]] = {}
    for c in heuristic_candidates(raw):
        if c.predicate in AI_PREDICATES:
            for n in set(c.lines) - state_lines(c, statements):
                readings.setdefault(n, []).append(c)
    return readings


def _reads(control: Control, candidate: _Candidate) -> bool:
    return (candidate.predicate in control.needs
            and _SUBJECTS.get(control.control_id, candidate.subject) == candidate.subject)


def _related(predicate: str, subject: Optional[str], s: Statement) -> bool:
    """The line (with its block headers) names vocabulary of the setting and no limit / counter / lockout."""
    context = _context(s)
    parts = {p for t in context for p in _parts(t)}
    if parts & L.UNRELATED or set(context) & L.RULE_WORDS:
        return False
    if predicate == PROTOCOL_ENABLED:
        return bool(parts & L.MGMT_PROTOCOLS.get(subject, frozenset())) and not parts & L.NOT_A_SERVER
    if predicate == DISCOVERY_PROTOCOL:
        return subject in L.DISCOVERY and subject in parts
    if predicate == SSH_VERSION:
        return bool(parts & L.SSH and parts & L.SSH_VERSION_RELATED)
    if predicate == NTP_AUTHENTICATED:
        return bool(parts & L.TIME_RELATED and parts & L.AUTH_RELATED)
    return bool(parts & _RELATED.get(predicate, frozenset()))


def _mentions(control: Control, s: Statement, readings: dict[int, list[_Candidate]]) -> bool:
    """The line states one of the control's AI-readable settings, as the lexicon reads it or by related words."""
    if any(_reads(control, c) for c in readings.get(s.line, ())):
        return True
    subjects = {_SUBJECTS[control.control_id]} if control.control_id in _SUBJECTS else {None, *L.DISCOVERY}
    return any(_related(p, subject, s) for p in control.needs if p in AI_PREDICATES for subject in subjects)


def _target_lines(control: Control, cited: list[int], statements: list[Statement],
                  readings: dict[int, list[_Candidate]]) -> list[int]:
    """Lines whose scopes the AI sees for a control: its own evidence about its settings, else a few related lines."""
    by_line = {s.line: s for s in statements}
    own = [n for n in cited if n in by_line and _mentions(control, by_line[n], readings)]
    # ponytail: first MAX_RELATED related lines in config order; rank by relatedness if prompts miss the right one
    return own or [s.line for s in statements if _mentions(control, s, readings)][:MAX_RELATED]


def _excerpt(raw: list[str], paths: list[tuple[str, ...]], statements: list[Statement], s: Statement) -> list[int]:
    """The line's tokenizer scope: its block siblings (nearest MAX_BLOCK_LINES) and enclosing block headers."""
    if s.scope_path:
        siblings = sorted((o.line for o in statements if (o.scope_path, o.block) == (s.scope_path, s.block)),
                          key=lambda n: abs(n - s.line))[:MAX_BLOCK_LINES]
    else:
        siblings = [s.line]
    headers, n = [], s.line - 1
    for header in reversed(paths[s.line - 1]):
        while n >= 1 and _header(raw[n - 1].strip().removesuffix("{").strip() or "{") != header:
            n -= 1
        if n >= 1:
            headers.append(n)
    return [*headers, *siblings]


def _prompt(controls: list[Control], scopes: dict[str, list[Statement]], numbers: list[int],
            shown: dict[int, str], discover: set[str]) -> str:
    questions = []
    for c in controls:
        facts = "; ".join(f"{p} ({'true or false' if p in BOOL_PREDICATES else _VALUE_FORMATS[p]})"
                          for p in c.needs if p in AI_PREDICATES)
        subject = f"; subject: {_SUBJECTS[c.control_id]}" if c.control_id in _SUBJECTS else ""
        where = " | ".join(dict.fromkeys(" > ".join(s.scope_path) or "top level" for s in scopes[c.control_id]))
        task = "\n  task: discover (no setting was found; an empty answer is expected unless a line states it)" \
            if c.control_id in discover else ""
        questions.append(f"- {c.control_id}: {c.question}\n  facts: {facts}{subject}\n  scope: {where}{task}")
    excerpt, previous = [], None
    for ref, n in enumerate(numbers, 1):
        if previous is not None and n != previous + 1:
            excerpt.append("...")
        excerpt.append(f"[{ref}] {shown[n]}")
        previous = n
    return ("QUESTIONS\n" + "\n".join(questions) + "\n\nCONFIGURATION EXCERPT (secrets redacted)\n"
            + fence(excerpt))


# ── request, budget, cache ──────────────────────────────────────────────────

def _request(prompt: str, budget: Budget, config: NormalizedConfig, controls: list[Control]) -> Optional[list]:
    if budget.remaining <= 0:
        return _unjudged(config, controls, "the AI call budget for this scan is used up")
    budget.remaining -= 1
    budget.calls += 1
    try:
        response = request_structured(
            prompt=prompt, response_format=RESPONSE_FORMAT, system_instruction=SYSTEM_PROMPT, model=MODEL,
            temperature=0.0, top_p=1.0, max_tokens=4096, timeout=30.0, seed=42, reasoning_effort="low",
        )
    except Exception as e:  # the client should not raise; a scan never breaks on the AI
        response = StructuredResponse(error=ERROR_REQUEST_FAILED, detail=str(e)[:300])
    proposals = response.data.get("proposals") if response.ok and isinstance(response.data, dict) else None
    if not isinstance(proposals, list):
        if response.quota_exhausted:
            budget.remaining = 0
        return _unjudged(config, controls, f"the AI judge was unavailable ({response.error or 'invalid output'})")
    return proposals


def _unjudged(config: NormalizedConfig, controls: list[Control], reason: str) -> None:
    for control in controls:
        config.ai_notes[control.control_id] = reason
    return None


def _cache_get(key: str) -> Optional[list]:
    try:
        with get_connection() as conn:
            row = conn.execute("SELECT response FROM ai_judge_cache WHERE key = ?", (key,)).fetchone()
        cached = json.loads(row["response"]) if row else None
        return cached if isinstance(cached, list) else None
    except Exception as e:
        logger.warning("AI judge cache unavailable: %s", e)
        return None


def _cache_put(key: str, proposals: list) -> None:
    try:
        with get_connection() as conn:
            conn.execute("INSERT INTO ai_judge_cache (key, response, created_at) VALUES (?, ?, ?) "
                         "ON CONFLICT (key) DO UPDATE SET response = excluded.response, created_at = excluded.created_at",
                         (key, json.dumps(proposals), datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")))
    except Exception as e:
        logger.warning("AI judge cache unavailable: %s", e)


# ── verification ────────────────────────────────────────────────────────────

def _norm(text) -> str:
    return " ".join(str(text or "").split()).lower()


def verify(proposal, controls: list[Control], numbers: list[int], shown: dict[int, str],
           by_line: dict[int, Statement], readings: dict[int, list[_Candidate]],
           statements: list[Statement]) -> Optional[_Candidate]:
    """The proposal as a candidate fact when the cited lines themselves support it, else None."""
    if not isinstance(proposal, dict):
        return None
    control = next((c for c in controls if c.control_id == proposal.get("control_id")), None)
    predicate = proposal.get("predicate")
    if control is None or predicate not in control.needs or predicate not in AI_PREDICATES:
        return None
    refs = proposal.get("line_refs")
    try:
        if not isinstance(refs, list) or not refs or any(not 1 <= int(ref) <= len(numbers) for ref in refs):
            return None
        cited = sorted({numbers[int(ref) - 1] for ref in refs})
    except (TypeError, ValueError):
        return None
    evidence = _norm(proposal.get("evidence"))
    if not evidence or not any(evidence in _norm(shown[n]) for n in cited):
        return None

    subject = proposal.get("subject")
    subject = subject.strip().lower() if isinstance(subject, str) else None
    if predicate not in (PROTOCOL_ENABLED, DISCOVERY_PROTOCOL):
        subject = None
    # Every cited setting line must support the value: a lexicon reading must agree; an unfamiliar line
    # (no lexicon reading of this setting) must be related and state the value itself
    supports: dict[int, list[_Candidate]] = {}
    for n in cited:
        lexicon = [c for c in readings.get(n, ()) if c.predicate == predicate and c.subject == subject]
        if lexicon:
            if not all(_agrees(proposal, predicate, c) for c in lexicon):
                return None
            supports[n] = lexicon
        elif n in by_line and _related(predicate, subject, by_line[n]):
            if (stated := _stated(proposal, predicate, subject, by_line[n], statements)) is None:
                return None
            supports[n] = [stated]
    setting = sorted(supports)
    if not setting or not all(_reads(control, c) for n in setting for c in supports[n]):
        return None
    # the other cited lines may only be the block state lines those readings use
    if not set(cited) <= {line for n in setting for c in supports[n] for line in c.lines}:
        return None
    # one tokenizer scope: a top-level line is a scope of its own
    if len({(by_line[n].scope_path, by_line[n].block) if by_line[n].scope_path else n for n in setting}) != 1:
        return None

    reading = supports[setting[0]][0]
    value = [_norm(proposal.get("value"))] if predicate in (LOG_REMOTE_DESTINATION, NTP_SERVER) else reading.value
    return _Candidate(predicate, value, cited, subject=subject, scope=reading.scope, unit=reading.unit)


def _agrees(proposal: dict, predicate: str, reading: _Candidate) -> bool:
    """The AI's value equals the lexicon's reading of the line."""
    text = _norm(proposal.get("value"))
    if predicate in BOOL_PREDICATES:
        return text in ("true", "false") and reading.value is (text == "true")
    if predicate == SSH_VERSION:
        return text.isdigit() and reading.value == int(text)
    if predicate == IDLE_TIMEOUT:
        minutes = _minutes(proposal)
        return minutes is not None and reading.unit == "min" and abs(reading.value - minutes) < 1e-9
    return bool(IP.match(text)) and "/" not in text and text in reading.value


def _unit(proposal: dict) -> Optional[str]:
    """The AI's unit label as min / s / h (``minutes`` → min); the line must still write a unit word of that kind."""
    text = _norm(proposal.get("unit"))
    return next((unit for unit, words in _UNIT_WORDS.items() if text in words), None)


def _minutes(proposal: dict) -> Optional[float]:
    try:
        return float(_norm(proposal.get("value"))) * _UNITS[_unit(proposal)]
    except (KeyError, ValueError):
        return None


def _stated(proposal: dict, predicate: str, subject: Optional[str], s: Statement,
            statements: list[Statement]) -> Optional[_Candidate]:
    """The AI's value as an unfamiliar line itself states it (its words, numbers, units, addresses), else None."""
    text = _norm(proposal.get("value"))
    if predicate in BOOL_PREDICATES:
        if text not in ("true", "false"):
            return None
        ips = [v for v in s.values if IP.match(v)]
        words = set(s.key_tokens)
        value, lines = _polarity(s, statements)
        if predicate == SOURCE_RESTRICTED and ips:
            value, lines = not all(ip in L.ANY_ADDRESS for ip in ips), [s.line]
        elif predicate == SOURCE_RESTRICTED and words & (L.UNRESTRICTED | L.RESTRICTED):
            value, lines = not words & L.UNRESTRICTED, [s.line]
        elif predicate == CENTRAL_AAA and value is not False and any("/" not in ip for ip in ips):
            value, lines = True, [s.line]
        elif predicate == LOGIN_BANNER and value is None and s.values:
            value, lines = True, [s.line]
        if value is None or value is not (text == "true"):
            return None
        return _Candidate(predicate, value, lines, subject=subject)
    if predicate == SSH_VERSION:
        return _Candidate(predicate, int(text), [s.line]) if text.isdigit() and text in s.values else None
    if predicate == IDLE_TIMEOUT:
        unit, minutes = _unit(proposal), _minutes(proposal)
        if minutes is None:
            return None
        for v in s.values:
            match = _NUMBER.match(v)
            if not match or match.group(1) != text:
                continue
            written = {match.group(2)} if match.group(2) else set(s.key_tokens)
            if written & _UNIT_WORDS[unit]:
                return _Candidate(predicate, minutes, [s.line], unit="min")
        return None
    if _polarity(s, statements)[0] is False:
        return None
    if IP.match(text) and "/" not in text and text in s.values:
        return _Candidate(predicate, [text], [s.line])
    # a hostname is a value of the line, never its leading keyword (`ntp.server 10.0.0.1` names no host)
    # ponytail: dotted-name shape only; resolve against the config's DNS / address objects if names mislead
    if HOSTNAME.match(text) and not NUMBER.match(text) and text in [v.lower() for v in s.values] + s.key_tokens[1:]:
        return _Candidate(predicate, [text], [s.line])
    return None
