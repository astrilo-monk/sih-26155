"""
Seed write-back: deterministic remediation for configurations no dedicated parser reads.

A confirmed recognizer (shipped seed or one an administrator confirmed) states exactly how a dialect
writes a setting: its template, its typed slot and what each slot value means. The recognizer that
*read* a failing line can therefore *write* the secure line -the same reviewed template with only the
slot changed -without anyone, human or AI, supplying command text:

    decisive FAIL whose evidence a recognizer read
      → rewrite that line's slot to the value the same recognizer reads as secure
      → the same recognizer re-reads the new line (self-check)
      → edited copy, rescanned exactly like an unknown-vendor upload
      → FIXED only when the control is now a decisive PASS, no other control got worse and the
        copy is still read by generic analysis

Only a value on a line that is already there is changed, so the dialect's own syntax is kept. A setting
that needs the operator (which subnet may manage the device) is NEEDS_INPUT. A setting whose secure form
needs more than one slot -NTP authentication also needs a key the recognizer does not describe -and a
``{neg}`` toggle (``delete`` / ``no`` / ``undo`` differ per dialect) are not written: they stay with the
candidate path.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass
from typing import Callable, Optional

from app.adaptive.matcher import EXTRACTION_RECOGNIZER, compile_pattern, recognizer_slot
from app.controls.catalog import CONTROLS
from app.facts import lexicon as L
from app.facts.predicates import (
    DISCOVERY_PROTOCOL, IDLE_TIMEOUT, LOGIN_MAX_ATTEMPTS, PASSWORD_MIN_LENGTH, PROTOCOL_ENABLED, SOURCE_RESTRICTED,
    SOURCE_ROUTING, SSH_VERSION,
)
from app.facts.recognizers import _scope_matches, _stored_knowledge, recognizer_value, stated_value
from app.models.results import DECISIVE_ASSURANCE, Status
from app.remediation.engine import (
    INPUTS, Analysis, Check, Outcome, Plan, RemediationStatus, _join, _status_text, analyze_generic_text,
    no_regression,
)
from app.structure.tokenizer import NEGATIVE, POSITIVE, Statement, tokenize, tokenize_line

SECURE_IDLE_MINUTES = 10


@dataclass(frozen=True)
class Target:
    """What a failing reading of one predicate is rewritten to."""
    control_id: str
    secure: Callable[[object], bool]   # does a value the recognizer reads count as secure?
    want: object = None                # the value to write into the slot
    input: Optional[str] = None        # or: an operator value replacing the wildcard address


TARGETS = {
    (PROTOCOL_ENABLED, "telnet"): Target("MGMT-001", lambda v: v is False, want=False),
    (PROTOCOL_ENABLED, "http"): Target("MGMT-002", lambda v: v is False, want=False),
    (SSH_VERSION, None): Target("MGMT-007", lambda v: v == 2, want=2),
    (IDLE_TIMEOUT, None): Target("MGMT-006", lambda v: isinstance(v, (int, float)) and 0 < v <= 15,
                                 want=float(SECURE_IDLE_MINUTES)),
    (DISCOVERY_PROTOCOL, "lldp"): Target("BOUNDARY-003", lambda v: v is False, want=False),
    (DISCOVERY_PROTOCOL, "cdp"): Target("BOUNDARY-003", lambda v: v is False, want=False),
    (SOURCE_ROUTING, None): Target("BOUNDARY-002", lambda v: v is False, want=False),
    (SOURCE_RESTRICTED, None): Target("MGMT-003", lambda v: v is True, input="management_subnet"),
    (LOGIN_MAX_ATTEMPTS, None): Target("AUTH-001", lambda v: isinstance(v, (int, float)) and 0 < v <= 10, want=3),
    (PASSWORD_MIN_LENGTH, None): Target("AUTH-002", lambda v: isinstance(v, (int, float)) and v >= 8, want=12),
}
_ANTONYM = {"yes": "no", "no": "yes", "enable": "disable", "disable": "enable", "enabled": "disabled",
            "disabled": "enabled", "true": "false", "false": "true", "on": "off", "off": "on"}


class _NeedsInput(Exception):
    def __init__(self, name: str):
        super().__init__(name)
        self.name = name


def _slot_options(recognizer, kind: str, current: str, want=None) -> list[str]:
    """Slot texts to try, the dialect's own spelling first; the self-check picks the one that reads right."""
    if kind == "enum":
        table = json.loads(recognizer.constant_value or "{}")
        return [k for k in table if k != "*"] if isinstance(table, dict) else []
    if kind == "polarity":
        flipped = _ANTONYM.get(current.lower())
        return ([flipped] if flipped else []) + sorted(POSITIVE | NEGATIVE)
    if kind == "int":
        prefix = current[:len(current) - len(current.lstrip("vV"))] if current[:1] in "vV" else ""
        number = f"{want:g}" if isinstance(want, (int, float)) else "2"
        return [f"{prefix}{number}", number]
    if kind == "duration":
        return [str(SECURE_IDLE_MINUTES), str(SECURE_IDLE_MINUTES * 60), f"{SECURE_IDLE_MINUTES}m"]
    return []


def _reads(recognizer, line: str):
    """The value ``recognizer`` reads from ``line``, or None when it does not match."""
    match = compile_pattern(recognizer.command_pattern, EXTRACTION_RECOGNIZER).match(line)
    if not match:
        return None
    kind, argument = recognizer_slot(recognizer.command_pattern)
    try:
        value = recognizer_value(recognizer, (kind, argument, match.group("slot") if kind else None))
    except (ValueError, AttributeError):
        return None
    return stated_value(recognizer, value, tokenize_line(line) or Statement(0, line))


def secure_line(recognizer, target: Target, line: str, inputs: dict) -> Optional[str]:
    """``line`` with its slot rewritten so the same recognizer reads a secure value; None when it cannot be."""
    match = compile_pattern(recognizer.command_pattern, EXTRACTION_RECOGNIZER).match(line)
    if not match:
        return None
    if target.input is not None:
        # a setting stated by naming a thing: keep the line, replace the wildcard that made it insecure
        tokens = line.split()
        wildcards = [t for t in tokens if t in L.ANY_ADDRESS or t.lower() in L.UNRESTRICTED]
        if not wildcards:
            return None
        if target.input not in inputs:
            raise _NeedsInput(target.input)
        new = line.replace(wildcards[0], str(inputs[target.input]), 1)
        return new if target.secure(_reads(recognizer, new)) else None
    kind, _ = recognizer_slot(recognizer.command_pattern)
    if kind in (None, "neg", "any") or "slot" not in match.groupdict() or match.group("slot") is None:
        return None
    start, end = match.span("slot")
    for option in _slot_options(recognizer, kind, match.group("slot"), target.want):
        new = line[:start] + option + line[end:]
        if new != line and target.secure(_reads(recognizer, new)):
            return new
    return None


def _failing(analysis: Analysis, control_id: str) -> list:
    return [r for r in analysis.control(control_id) if r.status == Status.FAIL and r.assurance in DECISIVE_ASSURANCE]


def rewrites(text: str, control_id: str, inputs: dict, before: Analysis) -> dict[int, str]:
    """Line number → secure line, for every line the control's decisive FAIL cites that a recognizer read.

    Raises ``_NeedsInput`` when a rewrite exists once the operator supplies a value."""
    cited = {n for r in _failing(before, control_id) for n in r.evidence.line_numbers}
    recognizers, _ = _stored_knowledge()
    lines = text.splitlines()
    changes: dict[int, str] = {}
    for statement in tokenize(lines):
        if statement.line not in cited:
            continue
        for recognizer in recognizers:
            target = TARGETS.get((recognizer.predicate, recognizer.subject))
            if target is None or target.control_id != control_id:
                continue
            if recognizer.scope_template and not _scope_matches(recognizer.scope_template, statement):
                continue
            original = lines[statement.line - 1]
            reading = _reads(recognizer, original.strip())
            if reading is None or target.secure(reading):
                continue
            new = secure_line(recognizer, target, original.strip(), inputs)
            if new is not None:
                # the line keeps its own indentation
                changes[statement.line] = original[:len(original) - len(original.lstrip())] + new
                break
    return changes


def _identity(recognizer, line: str) -> Optional[str]:
    """The line without its value: two lines with the same identity set the same thing."""
    match = compile_pattern(recognizer.command_pattern, EXTRACTION_RECOGNIZER).match(line)
    if not match:
        return None
    if "slot" in match.groupdict() and match.group("slot") is not None:
        start, end = match.span("slot")
        return " ".join((line[:start] + "{value}" + line[end:]).split())
    return " ".join(line.split())


def _negates(recognizer, line: str) -> bool:
    """The line is the recognizer's ``{neg}`` form, with its leading negator."""
    match = compile_pattern(recognizer.command_pattern, EXTRACTION_RECOGNIZER).match(line)
    kind, _ = recognizer_slot(recognizer.command_pattern)
    return bool(match) and kind == "neg" and bool(match.group("slot"))


def applied_command(text: str, command: str, control_id: str) -> Optional[str]:
    """A copy of ``text`` with ``command`` applied -or None unless a reviewed recognizer reads every line of it.

    Each line must be read, on its own and outside any block, by a confirmed recognizer for a setting this
    control consumes: a command that also does anything the engine cannot read is not applied at all. A
    configuration line the same recognizer reads with the same identity (the line without its value) is
    replaced in place; a line setting something the file does not state yet is added at the end.
    """
    recognizers = [r for r in _stored_knowledge()[0]
                   if not r.scope_template and r.predicate in CONTROLS[control_id].needs]
    lines = text.splitlines()
    for raw in command.splitlines():
        line = raw.strip()
        if not line:
            continue
        recognizer = next((r for r in recognizers if _reads(r, line) is not None), None)
        if recognizer is None or _negates(recognizer, line):
            # a negation (``no …``, ``delete …``, ``undo …``) removes a line from a configuration, it is never
            # one: the candidate path's removal check handles it
            return None
        identity = _identity(recognizer, line)
        same = [n for n, existing in enumerate(lines) if _identity(recognizer, existing.strip()) == identity]
        for n in same:
            lines[n] = lines[n][:len(lines[n]) - len(lines[n].lstrip())] + line
        if not same:
            lines.append(line)
    # an added line ends the file, so the copy always ends with a newline
    return "\n".join(lines) + "\n"


def verify(before: Analysis, after: Analysis, control_id: Optional[str]) -> list[Check]:
    """Rescan checks for a generic-path copy. ``control_id`` None: the whole plan (regressions and path)."""
    checks = []
    if control_id is not None:
        target = after.control(control_id)
        passed = bool(target) and all(r.status == Status.PASS and r.assurance in DECISIVE_ASSURANCE for r in target)
        checks.append(Check(
            "target", passed,
            f"{control_id} now passes: {target[0].reason}" if passed else
            f"{control_id} is {_status_text(target)} after the change, not a confirmed pass",
        ))
    checks.append(no_regression(before, after, control_id))
    still_generic = not after.identification.confirmed
    checks.append(Check(
        "generic_path", still_generic,
        "The corrected copy is still read by generic analysis" if still_generic else
        f"The corrected copy now matches the {after.identification.detected_vendor.value} grammar: "
        "rescan it as that vendor instead",
    ))
    return checks


def writeback_control(text: str, control_id: str, inputs: dict, before: Optional[Analysis] = None,
                      command: Optional[str] = None) -> tuple[Outcome, Optional[Analysis]]:
    """Remediate one control of a generic-path configuration. Returns the outcome and the verified rescan.

    ``command``: a candidate an administrator confirmed (typed, or drafted by the AI). It is applied only
    when a reviewed recognizer reads every line of it, and verified exactly like a written-back line."""
    before = before or analyze_generic_text(text)
    config = before.config
    outcome = Outcome(control_id, RemediationStatus.NOT_FAILING, "",
                      hostname=config.device.hostname if config else "unknown", vendor="unknown")
    results = before.control(control_id)
    outcome.control_status_before = _status_text(results)
    outcome.before = before.summary()
    fails = _failing(before, control_id)
    if not fails:
        outcome.reason = f"{control_id} has no decisive FAIL ({outcome.control_status_before}): nothing to change"
        return outcome, None
    outcome.scopes = [r.scope for r in fails if r.scope]
    outcome.evidence = list(dict.fromkeys((n, t) for r in fails for n, t in zip(r.evidence.line_numbers, r.evidence.text)))
    lines = text.splitlines()
    if command is not None:
        new_text = applied_command(text, command, control_id)
        if new_text is None:
            outcome.status = RemediationStatus.NO_RECIPE
            outcome.reason = (f"Not every line of the command is read by a reviewed recognizer for {control_id}, "
                              "so its effect cannot be checked")
            return outcome, None
        new_lines = new_text.splitlines()
        outcome.explanation = ("Your confirmed command, applied to a copy: a reviewed recognizer reads every line of "
                               "it, so the rescan can check exactly what it does.")
    else:
        outcome.inputs = [t.input for t in TARGETS.values() if t.control_id == control_id and t.input]
        try:
            changes = rewrites(text, control_id, inputs, before)
        except _NeedsInput as e:
            outcome.status, outcome.missing_inputs = RemediationStatus.NEEDS_INPUT, [e.name]
            outcome.reason = f"Provide {INPUTS[e.name].label} to generate this change"
            return outcome, None
        # the rescan decides whether the rewritten lines were all the control needed
        if not changes:
            outcome.status = RemediationStatus.NO_RECIPE
            outcome.reason = (f"No reviewed recognizer can write the secure form of every line {control_id} "
                              "cites; propose or review a command instead")
            return outcome, None
        new_lines = [changes.get(n, line) for n, line in enumerate(lines, 1)]
        new_text = _join(new_lines, text)
        outcome.explanation = ("Written by the same reviewed recognizer that read the failing line: only its value "
                               "changes, so the line keeps this configuration's own syntax.")
    outcome.fixed_config = new_text
    outcome.diff = "\n".join(difflib.unified_diff(lines, new_lines, "before", "after", n=2, lineterm=""))
    after = analyze_generic_text(new_text)
    outcome.after = after.summary()
    outcome.control_status_after = _status_text(after.control(control_id))
    outcome.checks = verify(before, after, control_id)
    failed = [c.detail for c in outcome.checks if not c.passed]
    if failed:
        outcome.status = RemediationStatus.VERIFICATION_FAILED
        outcome.reason = "Verification failed: " + "; ".join(failed)
        return outcome, None
    outcome.status = RemediationStatus.FIXED
    outcome.reason = next(c.detail for c in outcome.checks if c.name == "target")
    return outcome, after


def writeback_all(text: str, inputs: dict, skip: frozenset[str] | set[str] = frozenset(),
                  commands: Optional[dict[str, str]] = None) -> Plan:
    """Every failing control of a generic-path configuration, each step verified against the previous text.

    ``commands``: control → a command an administrator confirmed for it. It is tried first, and a written-back
    line is the fallback when it does not verify."""
    commands = commands or {}
    original = current = analyze_generic_text(text)
    outcomes = []
    for control_id in CONTROLS:
        if not any(r.status == Status.FAIL for r in original.control(control_id)):
            continue
        if control_id in skip or not _failing(original, control_id):
            outcomes.append(Outcome(control_id, RemediationStatus.PROVISIONAL,
                                    "Only a provisional (heuristic or AI) verdict exists: confirm it before remediation",
                                    hostname=original.config.device.hostname, vendor="unknown"))
            continue
        outcome, after = None, None
        if control_id in commands:
            outcome, after = writeback_control(current.text, control_id, inputs, current, commands[control_id])
        if after is None:
            outcome, after = writeback_control(current.text, control_id, inputs, before=current)
        if after is not None:
            current = after
            outcome.fixed_config = None  # the plan keeps one combined output
        outcomes.append(outcome)
    changed = current is not original
    return Plan(
        hostname=original.config.device.hostname if original.config else "unknown",
        vendor="unknown",
        vendor_status=original.identification.status,
        outcomes=outcomes,
        before=original.summary(),
        after=current.summary(),
        checks=verify(original, current, None) if changed else [],
        fixed_config=current.text if changed else None,
    )
