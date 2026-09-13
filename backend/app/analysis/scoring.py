"""
Security score calculation.

Simple penalty-based scoring: start at 100, subtract points
for each finding based on severity. Floor is 0.

The scoring is deliberately simple and transparent so users
can understand exactly why their score is what it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.controls.catalog import CONTROLS
from app.models.findings import Finding, Severity
from app.models.results import DECISIVE_ASSURANCE, ControlResult, Status


SEVERITY_PENALTIES = {
    Severity.CRITICAL: 12,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}


def calculate_score(findings: list[Finding]) -> int:
    """
    DEPRECATED (Phase 3): legacy score, kept for one phase. Use calculate_posture.

    Calculate a security score from 0-100.

    Each finding deducts points based on severity.
    The more (and worse) the findings, the lower the score.
    """
    total_penalty = sum(
        SEVERITY_PENALTIES.get(f.severity, 0)
        for f in findings
    )

    score = max(0, 100 - total_penalty)
    return score


# ---------------------------------------------------------------------------
# Scoring v2: posture + coverage over control results
# ---------------------------------------------------------------------------

WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}


@dataclass
class Posture:
    # Σw(PASS) / Σw(PASS + FAIL) × 100 over decisive results; None when nothing decided
    posture: Optional[int] = None
    # Σw(decided) / Σw(applicable) × 100; applicable = everything except N/A
    coverage: int = 0
    # Posture if every undecided control failed … if every undecided control passed
    bounds: Optional[tuple[int, int]] = None
    # Critical controls that are applicable but not decisively decided
    critical_unassessed: list[str] = field(default_factory=list)


def _control_outcome(results: list[ControlResult]) -> tuple[str, Severity]:
    """Collapse one control's results on one device into (pass|fail|undecided|n_a, weight severity).

    A control failing on several scopes counts once, at its worst failure
    severity, so one question never outweighs the others. Heuristic / AI
    verdicts are provisional and count as undecided.
    """
    control = CONTROLS[results[0].control_id]
    fails = [r for r in results if r.status == Status.FAIL]
    if fails:
        severity = max((r.failure.severity if r.failure else control.severity for r in fails),
                       key=WEIGHTS.__getitem__)
        decisive = any(r.assurance in DECISIVE_ASSURANCE for r in fails)
        return ("fail" if decisive else "undecided"), severity
    result = results[0]
    if result.status == Status.N_A:
        return "n_a", control.severity
    if result.status == Status.PASS and result.assurance in DECISIVE_ASSURANCE:
        return "pass", control.severity
    return "undecided", control.severity


def _percent(part: int, whole: int) -> int:
    return round(part * 100 / whole)


def calculate_posture(device_results: list[list[ControlResult]]) -> Posture:
    """Posture and coverage over every device's control results."""
    passed = failed = undecided = 0
    critical: set[str] = set()
    for results in device_results:
        by_control: dict[str, list[ControlResult]] = {}
        for r in results:
            by_control.setdefault(r.control_id, []).append(r)
        for control_id, group in by_control.items():
            outcome, severity = _control_outcome(group)
            w = WEIGHTS[severity]
            if outcome == "pass":
                passed += w
            elif outcome == "fail":
                failed += w
            elif outcome == "undecided":
                undecided += w
                if CONTROLS[control_id].severity == Severity.CRITICAL:
                    critical.add(control_id)

    applicable = passed + failed + undecided
    if not applicable:
        return Posture()
    return Posture(
        posture=_percent(passed, passed + failed) if passed + failed else None,
        coverage=_percent(passed + failed, applicable),
        bounds=(_percent(passed, applicable), _percent(passed + undecided, applicable)),
        critical_unassessed=sorted(critical),
    )
