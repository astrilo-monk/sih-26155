"""
Security score calculation.

Simple penalty-based scoring: start at 100, subtract points
for each finding based on severity. Floor is 0.

The scoring is deliberately simple and transparent so users
can understand exactly why their score is what it is.
"""

from __future__ import annotations
from app.models.findings import Finding, Severity


SEVERITY_PENALTIES = {
    Severity.CRITICAL: 12,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}


def calculate_score(findings: list[Finding]) -> int:
    """
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
