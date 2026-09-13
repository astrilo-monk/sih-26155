"""
Adaptive Interpretation Service.

Receives unrecognized security-relevant lines from a single
NormalizedConfig and produces AI semantic interpretations.

The AI is an interpreter ONLY. It maps a line onto the controlled
vocabulary of settable NormalizedConfig fields (``app.models.field_catalog``)
and cites the evidence for the value. It NEVER determines compliance,
generates findings, calculates scores, or produces remediation.

Contract and safety properties:

* the response schema restricts ``normalized_field`` to the field catalog
  (plus ``"unknown"``); the prompt carries each field's type and value rules
* each target line is sent with its structural block path and a few
  surrounding lines, while every result stays keyed to the target line number
* every returned item is validated on its own — one malformed or invented
  item never discards the rest of the batch
* results are matched by line number (whitespace differences in the echoed
  line are tolerated); missing lines get one follow-up request
* transient failures are retried once, then the chunk is split; an exhausted
  usage quota stops further calls immediately
* anything that still fails is marked ``ai_unavailable`` — never guessed —
  and the deterministic scan continues unchanged

All Groq calls go through app.ai.client and are fully mocked in tests.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from pydantic import ValidationError

from app.ai.client import (
    ERROR_INVALID_OUTPUT,
    ERROR_QUOTA_EXHAUSTED,
    ERROR_RATE_LIMITED,
    ERROR_REQUEST_FAILED,
    StructuredResponse,
    is_available,
    request_structured,
)
from app.ai.redaction import UNKNOWN_SCOPE, Redactor
from app.ai.interpretation_schemas import (
    ConfidenceLevel,
    InterpretationResult,
    InterpretationStatus,
    NORMALIZED_FIELD_ALLOWLIST,
)
from app.models.field_catalog import FIELD_REGISTRY, SETTABLE_FIELDS
from app.models.normalized import NormalizedConfig, UnrecognizedLine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Groq model + generation settings
# ---------------------------------------------------------------------------

GROQ_MODEL = "openai/gpt-oss-120b"

# Extraction task: conservative, repeatable sampling. This improves
# consistency but is not relied on for correctness — every result is
# validated downstream.
TEMPERATURE = 0.0
TOP_P = 1.0
SEED = 42
# gpt-oss is a reasoning model; short reasoning keeps latency (and the
# chance of hitting the timeout) stable between identical scans.
REASONING_EFFORT = "low"

# Lines per request. Smaller batches keep one bad response from affecting
# many lines and keep each request well inside the output token budget.
MAX_LINES_PER_BATCH = 10
MAX_TOKENS_PER_CHUNK = 8192

# Context sent with each target line
CONTEXT_LINE_CHARS = 160

# One level of halving when a whole chunk keeps failing
MAX_SPLIT_DEPTH = 1

_CONFIDENCE_RANK = {ConfidenceLevel.LOW: 0, ConfidenceLevel.MEDIUM: 1, ConfidenceLevel.HIGH: 2}
_MEDIUM_CEILING = 0.84


def _reasoning_effort_for(model: str) -> Optional[str]:
    return REASONING_EFFORT if "gpt-oss" in model else None


# ---------------------------------------------------------------------------
# Structured output schema (derived from the field catalog)
# ---------------------------------------------------------------------------

def _build_response_format() -> dict:
    item_properties = {
        "line_number": {
            "type": "integer",
            "description": "Line number of the TARGET line",
        },
        "raw_line": {
            "type": "string",
            "description": "The TARGET line text",
        },
        "likely_vendor": {
            "type": "string",
            "description": "Vendor/OS whose syntax this is, lowercase, or 'unknown'",
        },
        "security_concept": {
            "type": "string",
            "description": "Vendor-independent snake_case security concept",
        },
        "normalized_field": {
            "type": "string",
            "enum": [*SETTABLE_FIELDS, "unknown"],
            "description": "Target field from the catalog, or 'unknown'",
        },
        "extracted_value": {
            "type": ["string", "null"],
            "description": "Value in the target field's format, or null",
        },
        "value_evidence": {
            "type": ["string", "null"],
            "description": "Exact substring of the TARGET line that proves the value",
        },
        "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
            "description": "Confidence that field and value are correct",
        },
        "numeric_confidence": {
            "type": ["number", "null"],
            "description": "Numeric confidence in [0, 1], inside the chosen band",
        },
        "reasoning": {
            "type": "string",
            "description": "One-sentence explanation",
        },
        "status": {
            "type": "string",
            "enum": ["interpreted", "unknown"],
            "description": "'interpreted' when mapped to a field, else 'unknown'",
        },
    }
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "interpretation_response",
            "description": (
                "Mapping of unrecognized configuration lines onto the "
                "vendor-neutral field catalog. One result per TARGET line."
            ),
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "interpretations": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": item_properties,
                            "required": list(item_properties),
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["interpretations"],
                "additionalProperties": False,
            },
        },
    }


INTERPRETATION_RESPONSE_FORMAT = _build_response_format()


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_TEMPLATE = """You are the extraction component of a vendor-agnostic network security auditor.
You map configuration lines from ANY vendor or operating system onto a fixed,
vendor-neutral model. You do not judge compliance, create findings, score, or
suggest fixes.

TARGET FIELDS - normalized_field must be exactly one of these names, or "unknown":
{field_catalog}

MAPPING RULES
1. Work out which setting the TARGET line configures. The block path and the
   context lines only help you read the syntax; interpret the target line.
2. If the line sets exactly one target field, return that field and the value
   in the field's value format:
   - true/false fields: the resulting state, not the literal keyword. Resolve
     negations: "disable-X no" means X is enabled ("true"); "no X", "X disable"
     and "X off" mean "false".
   - number fields: digits only.
   - list fields: the single item (host, address, method) this line adds.
   - text fields: the value as written, without surrounding quotes.
3. value_evidence: copy, character for character, the part of the target line
   that proves the value (for example the address, or the keyword and its
   argument). It must be a substring of the target line.
4. Use normalized_field "unknown", extracted_value null, value_evidence null and
   status "unknown" when the line configures something not in the list, needs
   several fields at once, or only makes sense as part of a larger object such
   as an interface, access rule, firewall policy, user account or VPN proposal.
5. Never invent field names and never return a value the target line does not
   support.

CONFIDENCE - how sure you are that the field and the value are right
- high (numeric 0.85-1.0): a keyword in the line clearly names the concept and
  the value is explicit or follows directly from an explicit keyword.
- medium (0.50-0.84): plausible, but depends on an abbreviation, an implied
  default or a keyword with more than one common meaning.
- low (below 0.50): mostly a guess.
An unfamiliar or unidentified vendor is NOT by itself a reason to lower
confidence: judge the wording of the line. numeric_confidence must lie inside
the band of the chosen confidence.

VENDOR
likely_vendor: the vendor or operating system whose syntax this is, lowercase
(for example "juniper_junos", "palo_alto", "mikrotik_routeros", "arista_eos"),
only when the syntax is distinctive to it; otherwise "unknown". The vendor
never changes the field mapping.

OUTPUT
Exactly one object per TARGET line, in the given order, with its line_number,
raw_line copied from the target line, a short snake_case security_concept and
a one-sentence reasoning.
"""


def _field_catalog_text() -> str:
    lines = []
    for name in SETTABLE_FIELDS:
        info = FIELD_REGISTRY[name]
        lines.append(f"- {name} [{info.type_category}]: {info.description}. Value: {info.value_rule}.")
    return "\n".join(lines)


INTERPRETATION_SYSTEM_PROMPT = _SYSTEM_PROMPT_TEMPLATE.format(field_catalog=_field_catalog_text())


def _clip(text: str) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= CONTEXT_LINE_CHARS else text[: CONTEXT_LINE_CHARS - 1] + "…"


def _context_scopes(context: list[str], paths: list[list[str]]) -> list[tuple[str, ...]]:
    if len(paths) == len(context):
        return [tuple(p) for p in paths]
    return [UNKNOWN_SCOPE] * len(context)


def _build_prompt(lines: list[UnrecognizedLine]) -> str:
    """User prompt: each TARGET line with its block path and nearby lines.

    Every configuration fragment is redacted before clipping, so no secret
    value (or a clipped piece of one) reaches the AI provider. Each context
    line is redacted with its own block path; without one, conservatively.
    """
    redactor = Redactor()
    blocks = []
    for ln in lines:
        parts = [f"[TARGET line {ln.line_number}]", redactor.line(ln.raw_line.strip(), ln.structural_path)]
        if ln.structural_path:
            parts.append("  block: " + " > ".join(_clip(redactor.line(h)) for h in ln.structural_path))
        before = [
            c for c in (
                _clip(redactor.line(x, scope))
                for x, scope in zip(ln.context_before, _context_scopes(ln.context_before, ln.context_before_paths))
            ) if c
        ]
        after = [
            c for c in (
                _clip(redactor.line(x, scope))
                for x, scope in zip(ln.context_after, _context_scopes(ln.context_after, ln.context_after_paths))
            ) if c
        ]
        if before:
            parts.append("  context before: " + " | ".join(before))
        if after:
            parts.append("  context after: " + " | ".join(after))
        blocks.append("\n".join(parts))

    return (
        "Map each TARGET line below. Block paths and context lines are read-only "
        "reading aids; do not return objects for them.\n\n"
        + "\n\n".join(blocks)
        + f"\n\nReturn exactly {len(lines)} object(s), one per TARGET line, in this order."
    )


# ---------------------------------------------------------------------------
# Result construction
# ---------------------------------------------------------------------------

_DEFAULT_UNAVAILABLE_REASON = (
    "AI interpretation unavailable — Groq call failed or returned invalid output"
)
_QUOTA_REASON = (
    "AI interpretation unavailable — the AI provider's usage quota is exhausted; "
    "nothing was inferred for this line"
)
_FAILURE_REASONS = {
    ERROR_RATE_LIMITED: "AI interpretation unavailable — the AI provider is rate-limiting requests",
    ERROR_INVALID_OUTPUT: "AI interpretation unavailable — the AI returned unusable output",
    ERROR_REQUEST_FAILED: "AI interpretation unavailable — the AI request failed or timed out",
    ERROR_QUOTA_EXHAUSTED: _QUOTA_REASON,
}


def _make_unavailable_result(line: UnrecognizedLine, reason: Optional[str] = None) -> InterpretationResult:
    """An ai_unavailable result: no field, no value, zero confidence — not a judgement."""
    return InterpretationResult(
        line_number=line.line_number,
        raw_line=line.raw_line,
        likely_vendor="unknown",
        security_concept="unknown",
        normalized_field="unknown",
        extracted_value=None,
        confidence=ConfidenceLevel.LOW,
        numeric_confidence=0.0,
        reasoning=reason or _DEFAULT_UNAVAILABLE_REASON,
        status=InterpretationStatus.AI_UNAVAILABLE,
    )


def _review_result(line: UnrecognizedLine, vendor: str, value: Optional[str], reasoning: str) -> InterpretationResult:
    """The AI answered, but not in a usable form — keep what it said, send to review."""
    return InterpretationResult(
        line_number=line.line_number,
        raw_line=line.raw_line,
        likely_vendor=vendor,
        security_concept="unknown",
        normalized_field="unknown",
        extracted_value=value,
        confidence=ConfidenceLevel.MEDIUM,
        numeric_confidence=0.5,
        reasoning=reasoning,
        status=InterpretationStatus.UNKNOWN,
    )


def _text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_ws(text: Any) -> str:
    return " ".join(str(text or "").split())


def _parse_item(item: dict, line: UnrecognizedLine) -> InterpretationResult:
    """Validate one AI item against its target line; never raises."""
    vendor = _text(item.get("likely_vendor")) or "unknown"
    concept = _text(item.get("security_concept")) or "unknown"
    field = item.get("normalized_field")
    value = _text(item.get("extracted_value"))
    evidence = _text(item.get("value_evidence"))
    reasoning = _text(item.get("reasoning")) or ""

    if not isinstance(field, str) or (field != "unknown" and field not in NORMALIZED_FIELD_ALLOWLIST):
        return _review_result(
            line, vendor, value,
            f"AI proposed an unsupported field {field!r} — needs review. {reasoning}".strip(),
        )

    try:
        confidence = ConfidenceLevel(str(item.get("confidence", "")).lower())
    except ValueError:
        confidence = ConfidenceLevel.LOW
    try:
        numeric = item.get("numeric_confidence")
        numeric = None if numeric is None else min(1.0, max(0.0, float(numeric)))
    except (TypeError, ValueError):
        numeric = None

    status = (
        InterpretationStatus.INTERPRETED
        if item.get("status") == InterpretationStatus.INTERPRETED.value
        else InterpretationStatus.UNKNOWN
    )

    # Contract: a mapped value must cite its evidence to be eligible for HIGH
    if (
        status == InterpretationStatus.INTERPRETED
        and field != "unknown"
        and value is not None
        and evidence is None
        and _CONFIDENCE_RANK[confidence] > _CONFIDENCE_RANK[ConfidenceLevel.MEDIUM]
    ):
        confidence = ConfidenceLevel.MEDIUM
        numeric = min(numeric if numeric is not None else 0.7, _MEDIUM_CEILING)
        reasoning = f"{reasoning} (no value evidence cited — capped at medium)".strip()

    if _normalize_ws(item.get("raw_line")).lower() != _normalize_ws(line.raw_line).lower():
        logger.info("AI echoed a different raw_line for line %d — using the original line", line.line_number)

    try:
        return InterpretationResult(
            line_number=line.line_number,
            raw_line=line.raw_line,
            likely_vendor=vendor,
            security_concept=concept,
            normalized_field=field,
            extracted_value=value,
            value_evidence=evidence,
            confidence=confidence,
            numeric_confidence=numeric,
            reasoning=reasoning,
            status=status,
        )
    except ValidationError as e:
        return _review_result(
            line, vendor, value, f"AI output for this line failed validation: {e.errors()[0].get('msg')}",
        )


def _match_items(items: list, chunk: list[UnrecognizedLine]) -> tuple[dict[int, InterpretationResult], list[UnrecognizedLine]]:
    """Key AI items to target lines by line number (text match as fallback)."""
    by_number = {ln.line_number: ln for ln in chunk}
    results: dict[int, InterpretationResult] = {}
    unmatched: list[dict] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            number = int(item.get("line_number"))
        except (TypeError, ValueError):
            number = None
        line = by_number.get(number)
        if line is None:
            unmatched.append(item)
            continue
        if number not in results:  # first answer for a line wins
            results[number] = _parse_item(item, line)

    for item in unmatched:
        text = _normalize_ws(item.get("raw_line")).lower()
        candidates = [
            ln for ln in chunk
            if ln.line_number not in results and _normalize_ws(ln.raw_line).lower() == text
        ]
        if len(candidates) == 1:
            results[candidates[0].line_number] = _parse_item(item, candidates[0])
        else:
            logger.warning("AI returned a result for an unknown line (%r) — ignoring", item.get("line_number"))

    missing = [ln for ln in chunk if ln.line_number not in results]
    return results, missing


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

@dataclass
class _RunState:
    quota_exhausted: bool = False
    requests: int = 0


def _request(chunk: list[UnrecognizedLine], model: str, timeout: float, state: _RunState) -> StructuredResponse:
    state.requests += 1
    try:
        return request_structured(
            prompt=_build_prompt(chunk),
            response_format=INTERPRETATION_RESPONSE_FORMAT,
            system_instruction=INTERPRETATION_SYSTEM_PROMPT,
            model=model,
            temperature=TEMPERATURE,
            top_p=TOP_P,
            max_tokens=MAX_TOKENS_PER_CHUNK,
            timeout=timeout,
            seed=SEED,
            reasoning_effort=_reasoning_effort_for(model),
        )
    except Exception as e:  # the client should not raise, but never let it break a scan
        logger.warning("Structured request raised for %d line(s): %s", len(chunk), e)
        return StructuredResponse(error=ERROR_REQUEST_FAILED, detail=str(e)[:300])


def _interpret_chunk(
    chunk: list[UnrecognizedLine],
    model: str,
    timeout: float,
    state: Optional[_RunState] = None,
    depth: int = 0,
) -> list[InterpretationResult]:
    """Interpret one chunk. Returns exactly one result per input line, in order."""
    state = state or _RunState()
    if state.quota_exhausted:
        return [_make_unavailable_result(ln, _QUOTA_REASON) for ln in chunk]

    response: Optional[StructuredResponse] = None
    items: Optional[list] = None
    for _ in range(1 if depth else 2):
        response = _request(chunk, model, timeout, state)
        if response.quota_exhausted:
            state.quota_exhausted = True
            break
        if response.ok:
            items = response.data.get("interpretations")
            if isinstance(items, list):
                break
            items = None
            response = StructuredResponse(error=ERROR_INVALID_OUTPUT, detail="No interpretations array")
        if not response.retryable:
            break

    if items is None:
        if state.quota_exhausted:
            return [_make_unavailable_result(ln, _QUOTA_REASON) for ln in chunk]
        if depth < MAX_SPLIT_DEPTH and len(chunk) > 1:
            mid = len(chunk) // 2
            logger.info("Chunk of %d lines failed — retrying as two halves", len(chunk))
            return (
                _interpret_chunk(chunk[:mid], model, timeout, state, depth + 1)
                + _interpret_chunk(chunk[mid:], model, timeout, state, depth + 1)
            )
        reason = _FAILURE_REASONS.get(response.error if response else None, _DEFAULT_UNAVAILABLE_REASON)
        logger.warning("AI interpretation failed for %d line(s): %s", len(chunk), response.detail if response else "")
        return [_make_unavailable_result(ln, reason) for ln in chunk]

    results, missing = _match_items(items, chunk)
    if missing and depth < MAX_SPLIT_DEPTH:
        logger.info("AI omitted %d of %d line(s) — requesting them again", len(missing), len(chunk))
        for result in _interpret_chunk(missing, model, timeout, state, depth + 1):
            results[result.line_number] = result

    return [
        results.get(ln.line_number)
        or _make_unavailable_result(ln, "AI interpretation unavailable — the AI returned no result for this line")
        for ln in chunk
    ]


def interpret_lines(
    unrecognized_lines: list[UnrecognizedLine],
    model: str = GROQ_MODEL,
    timeout: float = 30.0,
) -> list[InterpretationResult]:
    """
    Interpret unrecognized lines using Groq.

    Splits the input into deterministic chunks of ``MAX_LINES_PER_BATCH``
    (input order) and returns one result per input line, in input order.
    Failures only affect the lines they concern; they never raise.
    """
    if not unrecognized_lines:
        return []

    if not is_available():
        logger.info("Groq unavailable — marking %d lines ai_unavailable", len(unrecognized_lines))
        return [_make_unavailable_result(line) for line in unrecognized_lines]

    chunks = [
        unrecognized_lines[i : i + MAX_LINES_PER_BATCH]
        for i in range(0, len(unrecognized_lines), MAX_LINES_PER_BATCH)
    ]
    logger.info(
        "Interpreting %d lines in %d chunk(s) of up to %d lines each",
        len(unrecognized_lines), len(chunks), MAX_LINES_PER_BATCH,
    )

    state = _RunState()
    results: list[InterpretationResult] = []
    for chunk in chunks:
        results.extend(_interpret_chunk(chunk, model, timeout, state))

    logger.info("AI interpretation finished with %d request(s)", state.requests)
    return results
