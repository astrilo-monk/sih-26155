"""
AI remediation candidates: one proposal, for one control, on an unconfirmed vendor.

The AI is asked for command *text* only — never for a verdict, never for a vendor, never for a change
it applies itself. The answer is a structured proposal that goes through exactly the same review as a
command an administrator typed (``app.remediation.candidates``): deterministic validation,
simulation on a copy of the configuration where that is possible, and administrator confirmation.

What the model receives is the minimum the question needs: the control, its question, the guidance
the deterministic engine already produced, the vendor detection status, and the tokenizer scope of
the cited failing lines — the same excerpt rule the AI judge uses, with the whole configuration
redacted first and the prompt scrubbed of every known secret afterwards.

What comes back is accepted only if it is exactly the expected shape: the control that was asked, one
command, and nothing else. Unknown or missing fields are refused rather than repaired.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from app.adaptive.context import structural_paths
from app.ai.client import ERROR_INVALID_OUTPUT, ERROR_REQUEST_FAILED, StructuredResponse, request_structured
# the excerpt rule of the judge: the cited lines' block siblings plus their enclosing block headers
from app.ai.judge import _excerpt
from app.ai.redaction import Redactor
from app.controls.catalog import Control
from app.remediation.candidates import MAX_COMMAND_CHARS, CandidateError, clean_command
from app.structure.tokenizer import tokenize

logger = logging.getLogger(__name__)

MODEL = "openai/gpt-oss-120b"
CONFIDENCES = ("low", "medium", "high")

SYSTEM_PROMPT = """You are helping a network administrator remediate one security finding on a device
whose vendor the auditor could not confirm. You propose command text for a human to review.

RULES
1. Propose the single command (or the fewest lines) that removes or switches off exactly the setting
   the cited configuration lines state. Change nothing else.
2. Follow the syntax and the hierarchy of the excerpt: address the setting in the same block path the
   cited lines sit in, using the excerpt's own dialect.
3. Prefer an explicit removal or disable of the cited statement (for example a delete/no/unset form,
   or the same statement with a disable keyword) over a rewrite of the surrounding configuration.
4. Never propose a password, key, community, certificate or any other credential. Never propose a
   reload, factory reset, image change, or a command that erases configuration.
5. explanation: one sentence on what the command changes. assumptions: what you had to assume about
   the platform, as short phrases; an empty list is fine.
6. You do not decide compliance and your command is not applied. It is verified by deterministic code
   where possible and confirmed by a human. If you are unsure of the dialect, say so in assumptions."""

_FIELDS = {
    "control_id": {"type": "string"},
    "candidate_command": {"type": "string"},
    "explanation": {"type": "string"},
    "confidence": {"type": "string", "enum": list(CONFIDENCES)},
    "assumptions": {"type": "array", "items": {"type": "string"}},
}
RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "remediation_candidate",
        "strict": True,
        "schema": {
            "type": "object", "properties": _FIELDS, "required": list(_FIELDS), "additionalProperties": False,
        },
    },
}


@dataclass
class AIProposal:
    command: str
    explanation: str = ""
    confidence: str = ""
    assumptions: list[str] = None  # type: ignore[assignment]

    def __post_init__(self):
        self.assumptions = list(self.assumptions or [])


def _prompt(control: Control, recommendation: str, vendor_status: str, detected_vendor: str,
            scopes: list[str], excerpt: list[str]) -> str:
    return (
        f"FINDING\n- control: {control.control_id} — {control.title}\n"
        f"- question the auditor asks: {control.question}\n"
        f"- vendor-neutral guidance: {recommendation or 'none recorded'}\n"
        f"- device vendor detection: {vendor_status}"
        + (f" (the syntax resembles {detected_vendor}, unverified — this is evidence only, "
           "not a confirmed platform)" if detected_vendor and detected_vendor != "unknown" else "")
        + f"\n- block path of the failing lines: {' | '.join(scopes) or 'top level'}\n\n"
        "CONFIGURATION EXCERPT (secrets redacted; the cited failing lines are marked >>)\n"
        + "\n".join(excerpt)
    )


def propose_candidate(control: Control, raw_lines: list[str], evidence_lines: list[int],
                      recommendation: str = "", vendor_status: str = "unknown",
                      detected_vendor: str = "unknown") -> tuple[Optional[AIProposal], str]:
    """Ask for one candidate command. Returns the proposal, or None and a short failure detail."""
    if not evidence_lines:
        return None, "the finding cites no configuration line to change"
    statements = {s.line: s for s in tokenize(raw_lines)}
    cited = [n for n in sorted(set(evidence_lines)) if n in statements]
    if not cited:
        return None, "the cited lines carry no configuration statement"

    # redact the whole configuration first so every secret value is known, then scrub the excerpt as a whole
    redactor, paths = Redactor(), structural_paths(raw_lines)
    redacted = [redactor.line(text.rstrip(), paths[i]) for i, text in enumerate(raw_lines)]
    numbers = sorted({n for line in cited for n in _excerpt(raw_lines, paths, list(statements.values()),
                                                            statements[line])})
    shown = dict(zip(numbers, redactor.scrub("\n".join(redacted[n - 1] for n in numbers)).split("\n")))
    excerpt = [f"{'>>' if n in cited else '  '} {shown[n]}" for n in numbers]
    scopes = list(dict.fromkeys(" > ".join(statements[n].scope_path) for n in cited))
    prompt = redactor.scrub(_prompt(control, recommendation, vendor_status, detected_vendor, scopes, excerpt))

    try:
        response = request_structured(
            prompt=prompt, response_format=RESPONSE_FORMAT, system_instruction=SYSTEM_PROMPT, model=MODEL,
            temperature=0.0, top_p=1.0, max_tokens=1024, timeout=30.0, seed=42, reasoning_effort="low",
        )
    except Exception as e:  # the client should not raise; a candidate request never breaks the API
        response = StructuredResponse(error=ERROR_REQUEST_FAILED, detail=str(e)[:300])
    if not response.ok:
        return None, response.error or ERROR_INVALID_OUTPUT

    proposal, detail = _validated(response.data, control.control_id)
    if proposal is None:
        return None, detail
    # the model saw only redacted text, but never hand its output on without scrubbing it too
    proposal.command = redactor.scrub(proposal.command)
    proposal.explanation = redactor.scrub(proposal.explanation)
    proposal.assumptions = [redactor.scrub(a) for a in proposal.assumptions]
    return proposal, ""


def _validated(data, control_id: str) -> tuple[Optional[AIProposal], str]:
    """The answer as a proposal only if it is exactly the expected shape for the control that asked."""
    if not isinstance(data, dict) or set(data) != set(_FIELDS):
        return None, "the answer did not have the expected fields"
    if data.get("control_id") != control_id:
        return None, f"the answer was about {data.get('control_id')!r}, not {control_id}"
    assumptions = data.get("assumptions")
    if not isinstance(assumptions, list) or not all(isinstance(a, str) for a in assumptions):
        return None, "the answer's assumptions were not a list of text"
    if not isinstance(data.get("explanation"), str):
        return None, "the answer's explanation was not text"
    confidence = data.get("confidence")
    if confidence not in CONFIDENCES:
        return None, "the answer's confidence was not low, medium or high"
    try:
        command = clean_command(data.get("candidate_command"))
    except CandidateError as e:
        return None, str(e)
    return AIProposal(command=command, explanation=data["explanation"][:MAX_COMMAND_CHARS],
                      confidence=confidence, assumptions=[a[:200] for a in assumptions[:10]]), ""
