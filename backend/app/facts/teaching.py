"""
Resolving a control the scan left undecided.

    UNKNOWN / NOT_CONFIGURED control
      → lines of the uploaded configuration that mention the setting (the lexicon's reading of a
        line, else its related vocabulary); when none do, the person picks a line themselves
      → the person states what that line means for this control
      → ``draft_recognizer(..., asserted=…)`` -the same recognizer, the same safety gates
      → saved → the scan is re-evaluated → the control decides from CONFIRMED evidence, or stays undecided

Nothing here decides a control, and nothing here invents evidence. It only chooses what a person may
be asked about; the asserted meaning is still checked against the line itself by ``validate_recognizer``,
so a line that does not state the value cannot teach it.
"""

from __future__ import annotations

from typing import Iterable, Optional

from app.controls.catalog import Control
from app.facts import lexicon as L
from app.facts.heuristics import _Candidate, _context, _parts
from app.facts.predicates import DISCOVERY_PROTOCOL, PROTOCOL_ENABLED
from app.facts.recognizers import BOOL_PREDICATES, RECOGNIZER_PREDICATES, provisional_lines, recognizer_facts
from app.structure.tokenizer import Statement, tokenize

# Lines offered per control: enough to find the right one, few enough to read
MAX_SUGGESTED = 8
# Controls that read one subject of a shared predicate (the AI judge uses the same table)
SUBJECTS = {"MGMT-001": "telnet", "MGMT-002": "http"}


def teachable_predicates(control: Control) -> list[str]:
    """The control's settings a recognizer can answer."""
    return [p for p in control.needs if p in RECOGNIZER_PREDICATES]


def suggested_lines(raw_lines: list[str], control: Control,
                    extra: Iterable[_Candidate] = ()) -> list[tuple[int, Optional[_Candidate]]]:
    """Lines a person may be asked about for this control, best first.

    A line the lexicon (or a verified AI proposal) already reads comes with that reading; a line that
    only names the setting's vocabulary comes with none, and the person says what it means.
    """
    from app.ai.judge import _mentions, _readings  # the judge imports recognizers; keep the cycle open

    read = dict(provisional_lines(raw_lines, control.needs, extra))
    _, skip = recognizer_facts(raw_lines)
    statements = tokenize(raw_lines)
    lines: list[tuple[int, Optional[_Candidate]]] = [(n, read[n]) for n in sorted(read)]
    readings = _readings(raw_lines, statements)
    for s in statements:
        if len(lines) >= MAX_SUGGESTED:
            break
        if s.line in read or s.line in skip:
            continue
        if _mentions(control, s, readings):
            lines.append((s.line, None))
    return lines


def _subject(control: Control, predicate: str, statement: Optional[Statement]) -> Optional[str]:
    """The subject an asserted fact is about: fixed by the control, or the protocol the line names."""
    if control.control_id in SUBJECTS:
        return SUBJECTS[control.control_id]
    if predicate == DISCOVERY_PROTOCOL and statement is not None:
        words = {p for t in _context(statement) for p in _parts(t)}
        return next((d for d in sorted(L.DISCOVERY) if d in words), None)
    if predicate == PROTOCOL_ENABLED and statement is not None:
        words = {p for t in _context(statement) for p in _parts(t)}
        return next((name for name, spellings in sorted(L.MGMT_PROTOCOLS.items()) if words & spellings), None)
    return None


def meanings(raw_lines: list[str], control: Control, line_number: int) -> list[dict]:
    """What a person may say this line means for this control.

    A true/false setting offers both polarities -the line has to state the one that is chosen.
    A value setting (a version, a timeout, an address) offers only "this line states it": the value
    is read from the line, never from the person.
    """
    statement = next((s for s in tokenize(raw_lines) if s.line == line_number), None)
    options = []
    for predicate in teachable_predicates(control):
        subject = _subject(control, predicate, statement)
        if predicate in BOOL_PREDICATES:
            options += [{"predicate": predicate, "subject": subject, "value": v} for v in (True, False)]
        else:
            options.append({"predicate": predicate, "subject": subject, "value": None})
    return options


def asserted_candidate(raw_lines: list[str], control: Control, line_number: int,
                       predicate: str, value, subject: Optional[str] = None) -> _Candidate:
    """The candidate a person's answer stands for. Raises ``LookupError`` / ``ValueError`` when it cannot stand."""
    if predicate not in teachable_predicates(control):
        raise ValueError(f"'{predicate}' is not a setting {control.control_id} reads")
    statement = next((s for s in tokenize(raw_lines) if s.line == line_number), None)
    if statement is None:
        raise LookupError(f"Line {line_number} is not a configuration statement")
    if predicate in BOOL_PREDICATES and not isinstance(value, bool):
        raise ValueError("This setting is on or off: say which one the line states")
    if subject is None:
        subject = _subject(control, predicate, statement)
    # A value setting is read from the line, so the candidate carries whatever the line holds; the
    # drafted template lands on that token and ``validate_recognizer`` refuses a line without one.
    return _Candidate(predicate, value, [line_number], subject=subject)
