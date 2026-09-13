"""
Control results: the answer to one security question for one configuration.

A rule no longer answers only "here is a problem". Every control in the
catalog produces a result for every scanned config:

    PASS             the setting was found and is secure
    FAIL             the setting was found and is insecure (shown as a Finding)
    NOT_CONFIGURED   nothing relevant was found; not scored
    UNKNOWN          something relevant exists but could not be decided
    N_A              proven not to apply (the confirmed vendor lacks the concept)

``assurance`` records where the deciding evidence came from. Only PASS and
FAIL carry one. Security facts (``facts``) arrive in Phase 4.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from app.models.findings import Severity


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_CONFIGURED = "not_configured"
    UNKNOWN = "unknown"
    N_A = "n_a"


class Assurance(str, Enum):
    PARSER = "parser"            # read by a confirmed vendor parser
    CONFIRMED = "confirmed"      # admin-confirmed mapping / recognizer
    DEFAULT = "default"          # confirmed vendor's documented default
    HEURISTIC = "heuristic"      # lexicon heuristics (provisional)
    AI_VERIFIED = "ai_verified"  # AI proposal with verified citation (provisional)


DECIDED_STATUSES = frozenset({Status.PASS, Status.FAIL})
DECISIVE_ASSURANCE = frozenset({Assurance.PARSER, Assurance.CONFIRMED, Assurance.DEFAULT})


@dataclass
class Evidence:
    """Configuration lines a result cites (1-indexed) and their text."""
    line_numbers: list[int] = field(default_factory=list)
    text: list[str] = field(default_factory=list)
    scope_path: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.line_numbers)


@dataclass
class FailureDetail:
    """What a FAIL result shows to the user as a Finding."""
    severity: Severity
    description: str
    security_impact: str
    recommendation: str


@dataclass
class ControlResult:
    control_id: str
    status: Status
    reason: str
    device_hostname: str = "unknown"
    vendor: str = "unknown"
    assurance: Optional[Assurance] = None
    # Provisional verdict (heuristic / AI) awaiting confirmation — Phase 5+
    proposed_status: Optional[Status] = None
    # The object the result is about when a control is evaluated per scope
    # (an interface, a VTY range, an ACL, a firewall policy, an SNMP community)
    scope: Optional[str] = None
    evidence: Evidence = field(default_factory=Evidence)
    # SecurityFacts the decision was based on — Phase 4
    facts: list = field(default_factory=list)
    # Present exactly when status is FAIL
    failure: Optional[FailureDetail] = None

    @property
    def decided(self) -> bool:
        return self.status in DECIDED_STATUSES
