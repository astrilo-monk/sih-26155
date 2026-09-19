"""
Candidate remediation for unconfirmed vendors: proposed, deterministically checked, human-confirmed.

A confirmed vendor keeps the deterministic path of ``engine.py`` (recipes + full rescan) untouched.
A device whose vendor could not be confirmed has no recipe and no trusted grammar, so the command
text can only come from outside the engine — typed by the administrator, or proposed by the AI. Such
text is a **candidate**, never a fix:

    decisive FAIL of a control on an unconfirmed-vendor configuration
      → candidate command text (manual, or an AI proposal that passed a strict schema)
      → deterministic validation: shape and size, and whether the command addresses the failing
        statement in its own scope (its keywords plus every word of its block path)
      → simulation on an in-memory COPY: a negating command removes exactly the cited statements
      → the copy is re-read by the generic engine (tokenizer, confirmed recognizers, heuristics)
        and every control re-evaluated
      → VERIFIED when the targeted control no longer FAILs, no other control got worse and the copy
        is still read by generic analysis; REJECTED when the simulation does not hold; UNVERIFIED
        when no deterministic effect can be derived from the text at all
      → administrator confirmation (CONFIRMED)

A VERIFIED candidate keeps the edited copy it was verified against (``verified_config``) so the
administrator can download it: a *verified corrected copy of the uploaded configuration*, not a device
configuration NetAuditAI generated and not something applied anywhere. Every other status clears it.

Nothing here touches the stored scan, its configuration text, its results, posture or coverage, and
no command is executed anywhere: NetAuditAI never connects to a device. "Verified" means the text
removes the finding from this configuration *file* — not that it is safe to run on the device.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Iterable, Optional

from app.adaptive.context import structural_paths
from app.controls.catalog import CONTROLS, ControlKind
from app.models.results import DECISIVE_ASSURANCE, Status
from app.remediation.engine import Analysis, Check, _join, analyze_generic_text, no_regression
from app.structure.tokenizer import Statement, tokenize

MAX_COMMAND_CHARS = 2000
MAX_COMMAND_LINES = 20

SOURCE_MANUAL = "manual"
SOURCE_AI = "ai"
SOURCE_DERIVED = "derived"

# Controls a removal can honestly resolve: the configuration states something that must not be there.
# A control that REQUIRES a setting (remote logging, AAA, a banner) or holds one to a THRESHOLD (an idle
# timeout, a crypto proposal) is never derived from — deleting the line would leave the setting unset,
# which reads as "not configured" but is not an improvement. Those stay with the person who owns the
# command: typed by an administrator, or proposed by the AI, and confirmed by a human either way.
DERIVABLE_KINDS = frozenset({ControlKind.PROHIBITION, ControlKind.RELATIONAL})


class CandidateStatus(str, Enum):
    DRAFT = "draft"            # accepted for review; not simulated yet
    VERIFIED = "verified"      # simulated on a copy: the finding is gone and nothing else got worse
    UNVERIFIED = "unverified"  # accepted for review, but no deterministic effect could be derived
    REJECTED = "rejected"      # the simulation did not resolve the finding, or a human rejected it
    CONFIRMED = "confirmed"    # an administrator confirmed it (still never executed on a device)


class CandidateError(ValueError):
    """The candidate text cannot be accepted at all (shape, size, control characters)."""


@dataclass
class Candidate:
    """One proposed remediation for one control of one uploaded configuration."""
    config_index: int
    control_id: str
    source: str
    command: str
    explanation: str = ""
    confidence: str = ""
    assumptions: list[str] = field(default_factory=list)
    status: CandidateStatus = CandidateStatus.DRAFT
    reason: str = ""
    # the failing statements this candidate must address (before state)
    evidence: list[tuple[int, str]] = field(default_factory=list)
    control_status_before: Optional[str] = None
    control_status_after: Optional[str] = None
    checks: list[Check] = field(default_factory=list)
    diff: str = ""
    # The edited COPY of the uploaded configuration, kept only while this candidate is VERIFIED or
    # CONFIRMED-after-verification. It is scan memory only: never persisted, never the stored config,
    # never applied to a device. Any other status clears it, so nothing unverified can be handed out.
    verified_config: Optional[str] = None
    created_at: str = ""
    confirmed_at: Optional[str] = None

    @property
    def key(self) -> str:
        return f"{self.config_index}-{self.control_id}"


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ── validation ──────────────────────────────────────────────────────────────

def clean_command(text) -> str:
    """The candidate text as it will be shown and simulated, or raise :class:`CandidateError`."""
    if not isinstance(text, str):
        raise CandidateError("A candidate command must be text")
    if len(text) > MAX_COMMAND_CHARS:
        raise CandidateError(f"A candidate command may be at most {MAX_COMMAND_CHARS} characters")
    if any(ord(c) < 32 and c not in "\r\n\t" for c in text):
        raise CandidateError("A candidate command may not contain control characters")
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    if not lines:
        raise CandidateError("Enter the command that changes this setting on the device")
    if len(lines) > MAX_COMMAND_LINES:
        raise CandidateError(f"A candidate command may be at most {MAX_COMMAND_LINES} lines")
    return "\n".join(lines)


# ── what the candidate addresses ────────────────────────────────────────────

def _words(text: str) -> set[str]:
    """Every word of a block-path segment, as the tokenizer would read it (no braces, no quotes)."""
    return {w for raw in re.split(r"\s+", text.lower())
            if (w := raw.strip("{}();\"'")) and w not in ("set", "config", "edit")}


def _addressed(statement: Statement) -> set[str]:
    return ({t.lower() for t in statement.key_tokens} | {v.lower() for v in statement.values}
            | {w for segment in statement.scope_path for w in _words(segment)})


def _covers(command: list[Statement], target: Statement) -> bool:
    """A negating command statement names this configuration statement and every word of its scope.

    Vendor-neutral: the words come from the configuration and from the text the administrator or the
    AI wrote — no vendor table, no dialect branch. A command that is narrower (or about something
    else) does not cover the statement, and nothing is then simulated.
    """
    needed = {t.lower() for t in target.key_tokens} | {w for segment in target.scope_path for w in _words(segment)}
    return any(s.polarity is False and needed <= _addressed(s) for s in command)


def _ordered_words(segment: str) -> list[str]:
    """The words of a block-path segment, in the order the configuration writes them."""
    seen = []
    for raw in re.split(r"\s+", segment.lower()):
        word = raw.strip("{}();\"'")
        if word and word not in ("set", "config", "edit") and word not in seen:
            seen.append(word)
    return seen


def block_openers(raw_lines: list[str]) -> set[int]:
    """Lines that open a block, by number.

    Removing one of these alone would leave its block's contents (and its closer) orphaned, so a
    derived change never touches them — whatever the dialect, since the depth comes from the same
    structural reading the tokenizer uses (braces, ``config``/``edit``, indentation).
    """
    paths = structural_paths(raw_lines)
    openers = set()
    for index, line in enumerate(raw_lines):
        if not line.strip():
            continue
        following = next((k for k in range(index + 1, len(raw_lines)) if raw_lines[k].strip()), None)
        if following is not None and len(paths[following]) > len(paths[index]):
            openers.add(index + 1)
    return openers


def derived_command(text: str, evidence: Iterable[int]) -> Optional[str]:
    """The change NetAuditAI can state itself: remove exactly the lines this finding cites.

    Built from the configuration's own words — the cited statement's keywords inside the block path
    it sits in — so it needs no vendor grammar and claims none. It is the *change to this file*, and
    ``verify`` proves it by re-reading the edited copy; whether this text is also the device's CLI
    syntax is for the administrator to say.

    None when the change cannot be stated safely: no cited line, a line the file does not hold as a
    statement, or a block opener, which cannot be removed on its own without orphaning its contents.
    """
    raw_lines = text.splitlines()
    statements = {s.line: s for s in tokenize(raw_lines)}
    openers = block_openers(raw_lines)
    commands: list[str] = []
    for number in dict.fromkeys(evidence):
        statement = statements.get(number)
        if statement is None or number in openers or not statement.key_tokens:
            return None
        words = [w for segment in statement.scope_path for w in _ordered_words(segment)]
        words += [t.lower() for t in statement.key_tokens if t.lower() not in words]
        command = "delete " + " ".join(dict.fromkeys(words))
        if command not in commands:
            commands.append(command)
    if not commands or len(commands) > MAX_COMMAND_LINES:
        return None
    return "\n".join(commands)


def removed_lines(text: str, command: str, evidence: Iterable[int]) -> Optional[list[int]]:
    """Lines a negating candidate removes from a copy, or None when no effect can be derived.

    The only effect this engine can derive from unfamiliar command text is a negation: a statement
    the command explicitly removes or switches off (``delete …``, ``no …``, ``unset …``,
    ``… disable``). Every cited failing line must be covered, and every statement of the command must
    be about one of them — a command that also does something else is not simulated at all, because
    that part of its effect cannot be checked.
    """
    cited = sorted(set(evidence))
    if not cited:
        return None
    statements = {s.line: s for s in tokenize(text.splitlines())}
    targets = [statements[n] for n in cited if n in statements]
    if len(targets) != len(cited):
        return None
    command_statements = tokenize(command.splitlines())
    if not all(any(_covers([s], t) for t in targets) for s in command_statements):
        return None
    return cited if all(_covers(command_statements, t) for t in targets) else None


def apply_to_copy(text: str, lines_to_remove: Iterable[int]) -> str:
    """A copy of the configuration without those lines. The original string is never modified."""
    drop = set(lines_to_remove)
    return _join([line for n, line in enumerate(text.splitlines(), 1) if n not in drop], text)


# ── lifecycle ───────────────────────────────────────────────────────────────

def failing_evidence(analysis: Analysis, control_id: str) -> list[tuple[int, str]]:
    """The lines the control's decisive FAIL results cite, as the generic engine reads this text."""
    fails = [r for r in analysis.control(control_id)
             if r.status == Status.FAIL and r.assurance in DECISIVE_ASSURANCE]
    return list(dict.fromkeys((n, t) for r in fails for n, t in zip(r.evidence.line_numbers, r.evidence.text)))


def _status_text(analysis: Analysis, control_id: str) -> Optional[str]:
    return "/".join(dict.fromkeys(r.status.value for r in analysis.control(control_id))) or None


def new_candidate(text: str, config_index: int, control_id: str, source: str, command: str,
                  explanation: str = "", confidence: str = "", assumptions: Iterable[str] = ()) -> Candidate:
    """A validated draft. Nothing is simulated yet and nothing about the scan changes."""
    before = analyze_generic_text(text)
    return Candidate(
        config_index=config_index, control_id=control_id, source=source, command=clean_command(command),
        explanation=explanation, confidence=confidence, assumptions=list(assumptions),
        status=CandidateStatus.DRAFT, evidence=failing_evidence(before, control_id),
        control_status_before=_status_text(before, control_id), created_at=_now(),
        reason="Accepted for review. NetAuditAI has not checked it against this configuration yet.",
    )


def derive(text: str, config_index: int, control_id: str) -> Optional[Candidate]:
    """NetAuditAI's own candidate for one decisive failure, verified before it is offered.

        decisive FAIL → the lines it cites → remove exactly those from a copy → re-read the copy
        → the finding is gone and nothing else got worse → a candidate an administrator can confirm

    Returns None when there is nothing to derive — no decisive failure, a control a removal could not
    honestly resolve (see ``DERIVABLE_KINDS``), or a change that cannot be stated safely — and a
    REJECTED candidate when the simulation does not hold — an honest answer
    either way, and never an unverified one. Nothing about the scan changes.
    """
    control = CONTROLS.get(control_id)
    if control is None or control.kind not in DERIVABLE_KINDS:
        return None
    evidence = failing_evidence(analyze_generic_text(text), control_id)
    if not evidence:
        return None
    command = derived_command(text, (n for n, _ in evidence))
    if command is None:
        return None
    candidate = new_candidate(
        text, config_index, control_id, SOURCE_DERIVED, command,
        explanation=("NetAuditAI derived this from the configuration itself: the lines this finding cites, "
                     "removed from the block they sit in. It is a change to this configuration file — check "
                     "that the wording matches your device's command syntax before you use it."),
    )
    return verify(candidate, text)


def verify(candidate: Candidate, text: str) -> Candidate:
    """Simulate the candidate on a copy of ``text`` and re-read it with the generic engine."""
    before = analyze_generic_text(text)
    candidate.control_status_before = _status_text(before, candidate.control_id)
    candidate.evidence = failing_evidence(before, candidate.control_id)
    candidate.checks, candidate.diff, candidate.control_status_after = [], "", None
    candidate.verified_config = None  # a re-check starts with nothing downloadable

    lines = removed_lines(text, candidate.command, (n for n, _ in candidate.evidence))
    if lines is None:
        candidate.status = CandidateStatus.UNVERIFIED
        candidate.reason = (
            "Accepted for review, but it could not be verified automatically: NetAuditAI can only "
            "check a command that explicitly removes or switches off the exact lines this finding "
            "cites, in their own block. Review it yourself before you use it."
        )
        return candidate

    after_text = apply_to_copy(text, lines)
    after = analyze_generic_text(after_text)
    candidate.control_status_after = _status_text(after, candidate.control_id)
    candidate.diff = "\n".join(difflib.unified_diff(text.splitlines(), after_text.splitlines(),
                                                    "before", "after", n=2, lineterm=""))
    still_failing = [r for r in after.control(candidate.control_id) if r.status == Status.FAIL]
    candidate.checks = [
        Check("target", not still_failing,
              f"{candidate.control_id} {candidate.control_status_before} → {candidate.control_status_after} "
              "on the edited copy" if not still_failing else
              f"{candidate.control_id} still fails on the edited copy: "
              + "; ".join(dict.fromkeys(r.reason for r in still_failing))),
        no_regression(before, after, candidate.control_id),
        Check("generic_path", not after.identification.confirmed,
              "The edited copy is still read by generic analysis" if not after.identification.confirmed else
              f"The edited copy now matches the {after.identification.detected_vendor.value} grammar: "
              "rescan it as that vendor instead of trusting this candidate"),
    ]
    failed = [c.detail for c in candidate.checks if not c.passed]
    if failed:
        candidate.status = CandidateStatus.REJECTED
        candidate.reason = "The candidate did not hold up: " + "; ".join(failed)
        return candidate
    candidate.status = CandidateStatus.VERIFIED
    candidate.verified_config = after_text
    candidate.reason = (
        f"Verified against the uploaded configuration: {candidate.control_id} "
        f"{candidate.control_status_before} → {candidate.control_status_after} on a copy of it. This does not "
        "establish that the command is safe to run on the physical device."
    )
    return candidate


def downloadable(candidate: Candidate) -> bool:
    """Whether a verified corrected copy may be handed out for this candidate.

    Only a candidate the simulation verified (or one an administrator confirmed *after* it verified)
    has ``verified_config`` at all: a draft, an unverified or a rejected candidate never does.
    """
    return (candidate.status in (CandidateStatus.VERIFIED, CandidateStatus.CONFIRMED)
            and bool(candidate.verified_config))


def confirm(candidate: Candidate) -> Candidate:
    """An administrator accepts the candidate. It is still not applied to any device."""
    candidate.confirmed_at = _now()
    verified = candidate.status == CandidateStatus.VERIFIED
    candidate.status = CandidateStatus.CONFIRMED
    candidate.reason = (
        "Confirmed by an administrator. " + (
            "It was verified against the uploaded configuration; " if verified
            else "It could not be verified automatically; ")
        + "NetAuditAI has not connected to the device and has not changed it. Apply the command "
          "yourself, then scan the device configuration again."
    )
    return candidate


def reject(candidate: Candidate, reason: str = "") -> Candidate:
    candidate.status = CandidateStatus.REJECTED
    candidate.confirmed_at = None
    candidate.verified_config = None
    candidate.reason = reason.strip() or "Rejected by an administrator. Nothing was changed."
    return candidate
