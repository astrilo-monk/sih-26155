"""
Adaptive Interpretation Service.

Receives unrecognized security-relevant lines from a single
NormalizedConfig and produces AI semantic interpretations via
a single batched Groq request.

The AI is an interpreter ONLY. It determines semantic meaning
(vendor, security concept, normalized field, value, confidence,
reasoning). It NEVER determines compliance, generates findings,
calculates scores, or produces remediation.

All Groq calls go through app.ai.client and are fully mocked
in tests. The service is designed to fail safely: if Groq is
unavailable, timeout, or returns malformed output, affected
lines are marked ai_unavailable and the deterministic scan
continues unchanged.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.ai.client import generate_structured, is_available
from app.ai.interpretation_schemas import (
    BatchedInterpretationResponse,
    ConfidenceLevel,
    InterpretationResult,
    InterpretationStatus,
    NORMALIZED_FIELD_ALLOWLIST,
)
from app.models.normalized import NormalizedConfig, UnrecognizedLine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Groq model + structured output configuration
# ---------------------------------------------------------------------------

GROQ_MODEL = "openai/gpt-oss-120b"

# JSON Schema for structured output. Enforces:
# - required fields
# - enums for confidence/status
# - normalized_field restricted to allowlist + "unknown"
# - additionalProperties: false
INTERPRETATION_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "interpretation_response",
        "description": (
            "Semantic interpretation of unrecognized security-relevant "
            "configuration lines. One result per input line."
        ),
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "interpretations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "line_number": {
                                "type": "integer",
                                "description": "1-indexed line number in the original config",
                            },
                            "raw_line": {
                                "type": "string",
                                "description": "The original configuration line text",
                            },
                            "likely_vendor": {
                                "type": "string",
                                "description": "Vendor or vendor family the line likely belongs to",
                            },
                            "security_concept": {
                                "type": "string",
                                "description": "Vendor-independent security concept",
                            },
                            "normalized_field": {
                                "type": "string",
                                "description": (
                                    "Existing normalized field path, or 'unknown' "
                                    "if it cannot safely map to an existing field"
                                ),
                            },
                            "extracted_value": {
                                "type": ["string", "null"],
                                "description": "Value extracted from the line, if any",
                            },
                            "confidence": {
                                "type": "string",
                                "enum": ["high", "medium", "low"],
                                "description": "How confident the AI is",
                            },
                            "reasoning": {
                                "type": "string",
                                "description": "Concise explanation",
                            },
                            "status": {
                                "type": "string",
                                "enum": ["interpreted", "unknown", "ai_unavailable"],
                                "description": "Interpretation status",
                            },
                        },
                        "required": [
                            "line_number",
                            "raw_line",
                            "likely_vendor",
                            "security_concept",
                            "normalized_field",
                            "extracted_value",
                            "confidence",
                            "reasoning",
                            "status",
                        ],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["interpretations"],
            "additionalProperties": False,
        },
    },
}


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

INTERPRETATION_SYSTEM_PROMPT = """You are a network security configuration interpreter.

Your task is to analyze unrecognized configuration lines from a network device
and describe their SEMANTIC MEANING. You are NOT a compliance engine. You do NOT
determine PASS/FAIL, create findings, calculate scores, or generate remediation.

For each line, provide:
- likely_vendor: The vendor or vendor family this line likely belongs to
  (e.g. cisco_ios, fortinet, palo_alto, edge_os, unknown, generic)
- security_concept: A vendor-independent, snake_case security concept name
  (e.g. ssh_host_key_minimum, failed_login_lockout, telnet_console_exposure)
- normalized_field: The EXISTING normalized field path this maps to from the
  allowlist below. If you cannot safely map it to an existing field, use "unknown".
  DO NOT invent new field names.
- extracted_value: Any concrete value extracted from the line (e.g. "3072",
  "120", "telnet", "enabled"). Use null if no clear value.
- confidence: Your confidence in this interpretation (high, medium, low)
- reasoning: A concise 1-sentence explanation
- status: "interpreted" if you produced a meaningful interpretation,
  "unknown" if you cannot interpret the line safely

Normalized field allowlist (use EXACTLY these strings, or "unknown"):
{field_allowlist}

Rules:
- NEVER invent normalized field names. If uncertain, use "unknown".
- NEVER determine compliance or scoring.
- Be conservative. If a line is ambiguous, lower confidence or mark unknown.
- Match the line_number exactly as provided.
- Return exactly one interpretation object per input line, in the same order.
"""


def _build_prompt(lines: list[UnrecognizedLine]) -> str:
    """Build the user prompt containing all unrecognized lines for batched interpretation."""
    field_allowlist = sorted(NORMALIZED_FIELD_ALLOWLIST)
    field_list = "\n".join(f"  - {f}" for f in field_allowlist)

    lines_text = "\n".join(
        f"  Line {ln.line_number}: {ln.raw_line.strip()}"
        for ln in lines
    )

    return f"""Interpret the following unrecognized security-relevant configuration lines.

Normalized field allowlist:
{field_list}

Lines to interpret:
{lines_text}

Return exactly one interpretation per input line, in the same order."""



# Maximum lines per Groq request. The structured JSON response for each line
# is ~400-500 chars. At 15 lines the response stays well under 8192 output
# tokens even with verbose reasoning. Diagnostics confirmed:
#   10 lines → 4,192 chars (fits in 4096 tokens)
#   20 lines → 8,368 chars (fits in 8192 tokens)
#   52 lines → TRUNCATED at 4096 tokens (root cause of ai_unavailable)
MAX_LINES_PER_BATCH = 15

# Output token budget per chunk — 8192 comfortably fits 15 lines of
# structured interpretation output.
MAX_TOKENS_PER_CHUNK = 8192


def _interpret_chunk(
    chunk: list[UnrecognizedLine],
    model: str,
    timeout: float,
) -> list[InterpretationResult]:
    """
    Interpret a single chunk of unrecognized lines via one Groq request.

    Returns exactly one InterpretationResult per input line.
    On any failure, affected lines are marked ai_unavailable.
    """
    prompt = _build_prompt(chunk)

    try:
        raw_response = generate_structured(
            prompt=prompt,
            response_format=INTERPRETATION_RESPONSE_FORMAT,
            system_instruction=INTERPRETATION_SYSTEM_PROMPT,
            model=model,
            temperature=0.1,
            max_tokens=MAX_TOKENS_PER_CHUNK,
            timeout=timeout,
        )
    except Exception as e:
        logger.warning(
            "Groq structured call raised exception for chunk of %d lines: %s",
            len(chunk), e,
        )
        return [_make_unavailable_result(line) for line in chunk]

    if raw_response is None:
        logger.info(
            "Groq returned no response for chunk of %d lines — marking ai_unavailable",
            len(chunk),
        )
        return [_make_unavailable_result(line) for line in chunk]

    try:
        batched = BatchedInterpretationResponse(**raw_response)
    except Exception as e:
        logger.warning(
            "Pydantic validation failed for chunk of %d lines: %s",
            len(chunk), e,
        )
        return [_make_unavailable_result(line) for line in chunk]

    return _align_results(batched.interpretations, chunk)


def interpret_lines(
    unrecognized_lines: list[UnrecognizedLine],
    model: str = GROQ_MODEL,
    timeout: float = 30.0,
) -> list[InterpretationResult]:
    """
    Interpret a batch of unrecognized lines using Groq.

    Splits the input into chunks of MAX_LINES_PER_BATCH and sends one
    Groq request per chunk. Results are merged in original input order.

    On any per-chunk failure (exception, timeout, malformed output),
    only that chunk's lines are marked ai_unavailable — other chunks
    are unaffected. The deterministic scan is never broken by AI failures.

    Args:
        unrecognized_lines: Security-relevant unrecognized lines from one config.
        model: Groq model name.
        timeout: Request timeout in seconds.

    Returns:
        List of InterpretationResult, one per input line, in input order.
    """
    if not unrecognized_lines:
        return []

    # If Groq is unavailable at all, mark every line ai_unavailable
    if not is_available():
        logger.info("Groq unavailable — marking %d lines ai_unavailable", len(unrecognized_lines))
        return [
            _make_unavailable_result(line)
            for line in unrecognized_lines
        ]

    # Split into chunks
    chunks: list[list[UnrecognizedLine]] = []
    for i in range(0, len(unrecognized_lines), MAX_LINES_PER_BATCH):
        chunks.append(unrecognized_lines[i : i + MAX_LINES_PER_BATCH])

    logger.info(
        "Interpreting %d lines in %d chunk(s) of up to %d lines each",
        len(unrecognized_lines), len(chunks), MAX_LINES_PER_BATCH,
    )

    # Interpret each chunk and merge results
    all_results: list[InterpretationResult] = []
    for chunk_idx, chunk in enumerate(chunks):
        logger.info(
            "Interpreting chunk %d/%d (%d lines)",
            chunk_idx + 1, len(chunks), len(chunk),
        )
        chunk_results = _interpret_chunk(chunk, model, timeout)
        all_results.extend(chunk_results)

    return all_results


def _align_results(
    results: list[InterpretationResult],
    input_lines: list[UnrecognizedLine],
) -> list[InterpretationResult]:
    """
    Ensure exactly one valid result per input line.

    If the AI returned results that don't match the input lines
    (missing, duplicate, or mismatched line numbers), those lines
    are marked as ai_unavailable rather than fabricating data.
    """
    input_by_line = {ln.line_number: ln for ln in input_lines}
    result_by_line: dict[int, InterpretationResult] = {}

    for r in results:
        # Skip results with no matching input line
        if r.line_number not in input_by_line:
            logger.warning(
                "AI returned result for nonexistent line %s — ignoring", r.line_number
            )
            continue

        # Skip results whose raw_line doesn't match the input
        input_line = input_by_line[r.line_number]
        if r.raw_line != input_line.raw_line:
            logger.warning(
                "AI returned mismatched raw_line for line %s — marking ai_unavailable",
                r.line_number,
            )
            result_by_line[r.line_number] = _make_unavailable_result(input_line)
            continue

        result_by_line[r.line_number] = r

    # Build final list in input order, filling gaps with ai_unavailable
    final: list[InterpretationResult] = []
    for ln in input_lines:
        if ln.line_number in result_by_line:
            final.append(result_by_line[ln.line_number])
        else:
            final.append(_make_unavailable_result(ln))

    return final


def _make_unavailable_result(line: UnrecognizedLine) -> InterpretationResult:
    """Create an ai_unavailable result for a line when interpretation fails."""
    return InterpretationResult(
        line_number=line.line_number,
        raw_line=line.raw_line,
        likely_vendor=line.vendor,
        security_concept="unknown",
        normalized_field="unknown",
        extracted_value=None,
        confidence=ConfidenceLevel.LOW,
        reasoning="AI interpretation unavailable — Groq call failed or returned invalid output",
        status=InterpretationStatus.AI_UNAVAILABLE,
    )


def interpret_config(config: NormalizedConfig) -> list[InterpretationResult]:
    """
    Interpret all unrecognized lines in a NormalizedConfig.

    Convenience wrapper that calls interpret_lines() with the
    config's unrecognized_lines.

    Returns an empty list if there are no unrecognized lines.
    """
    return interpret_lines(config.unrecognized_lines)