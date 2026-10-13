"""
Control catalog -the security questions the auditor answers.

The controls are data, in ``backend/data/controls.json``: adding a check, a framework
mapping or a whole framework is an edit to that file, not to code. Each control states
its question, decision kind, the highest severity a FAIL can have, the security-fact
predicates it needs, the judge that decides it (a built-in one, or a rule written in the
file), the phase its fix belongs to, and its framework mappings with the exact framework
version. The file is validated when it loads: a check naming an unknown predicate, judge,
kind or vendor stops the service at start instead of silently never deciding.

Mapping sources (verified 2026-09-13):

* NIST SP 800-53 Rev. 5 -official OSCAL catalog, release 5.2.0
  (github.com/usnistgov/oscal-content). Every id below exists with this title
  and none is withdrawn. AU-8(1), formerly cited for NTP authentication, is
  withdrawn in Rev. 5 and moved to SC-45(1).
* DISA STIG -requirement ids and titles from the Network Device Management SRG
  (vendor-agnostic; the product STIGs derive their V-ids from these SRG ids).
  Only requirements whose wording a control actually answers are mapped.
* ISO/IEC 27001:2022 Annex A -control ids and titles as published in the
  standard. Annex A controls are organisational; a device-configuration control
  is evidence towards one, never proof that the Annex A control is met.
* CIS Benchmarks -item ids and titles as published in Tenable's audit files
  for the named benchmark version and profile level. Only items confirmed for
  that exact benchmark version are listed: a control without a verified item
  has no CIS mapping rather than a guessed one. CIS items are product-specific
  and are only attached to findings for that vendor.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from app.facts import predicates as P
from app.models.findings import Severity
from app.models.normalized import Vendor

DATA = Path(__file__).resolve().parents[2] / "data" / "controls.json"


class ControlKind(str, Enum):
    PROHIBITION = "prohibition"  # an insecure setting must be off
    REQUIREMENT = "requirement"  # a security setting must be present
    THRESHOLD = "threshold"      # a value must stay within a bound
    RELATIONAL = "relational"    # objects must reference each other correctly


# Framework ids the API and the reports name; a framework added in the data file needs no entry here
NIST = "NIST_800_53"
NIST_VERSION = "SP 800-53 Rev. 5 (5.2.0)"
CIS = "CIS"
STIG = "DISA_STIG"
ISO = "ISO_27001"

# Fix phases (``phase`` in the data file): applied and printed in this order
PHASES = {
    0: "Establish the safe path",
    1: "Harden",
    2: "Switch off what the safe path replaced",
    3: "Restrict management access",
}


@dataclass(frozen=True)
class Mapping:
    framework: str
    version: str
    requirement_id: str
    title: str
    # Set for product-specific benchmark items; None applies to every vendor
    vendor: Optional[Vendor] = None


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    question: str
    kind: ControlKind
    # Highest severity a FAIL of this control can have
    severity: Severity
    category: str
    mappings: tuple[Mapping, ...]
    # Security-fact predicates the control consumes
    needs: tuple[str, ...] = ()
    # The control asks about an optional feature (a VPN): a device that does not configure it at all
    # is N/A, not undecided. Only a confirmed vendor can prove the absence.
    optional_feature: str = ""
    # A built-in judge's name (app.controls.judges), or a rule ({"forbid": true}, {"max": 15} ...)
    judge: Any = None
    # Fix order (PHASES): a fix in a lower phase is applied and printed first
    phase: int = 1
    # Dialect label (a seed recognizer's vendor) -> reference command lines, verified on a copy before use
    remediation: dict = field(default_factory=dict, compare=False, hash=False)


class CatalogError(ValueError):
    """The controls data file names something the engine does not know."""


def _known_predicates(declared: dict) -> set[str]:
    return {v for k, v in vars(P).items() if k.isupper() and isinstance(v, str) and "." in v} | set(declared)


def load(path: Path = DATA) -> tuple[dict[str, Control], dict[str, str]]:
    """The controls and the boolean predicates the file declares, validated."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    declared = doc.get("predicates", {})
    for name, kind in declared.items():
        if kind != "bool":
            raise CatalogError(f"predicate {name}: only boolean predicates can be declared in data, not '{kind}'")
    predicates = _known_predicates(declared)
    controls: dict[str, Control] = {}
    for entry in doc["controls"]:
        cid = entry["id"]
        if cid in controls:
            raise CatalogError(f"{cid} is defined twice")
        unknown = [n for n in entry["needs"] if n not in predicates]
        if unknown:
            raise CatalogError(f"{cid} needs unknown predicate(s) {', '.join(unknown)}")
        if entry.get("phase", 1) not in PHASES:
            raise CatalogError(f"{cid}: phase must be one of {sorted(PHASES)}")
        try:
            controls[cid] = Control(
                control_id=cid, title=entry["title"], question=entry["question"],
                kind=ControlKind(entry["kind"]), severity=Severity(entry["severity"]), category=entry["category"],
                mappings=tuple(Mapping(m["framework"], m["version"], m["id"], m["title"],
                                       Vendor(m["vendor"]) if m.get("vendor") else None)
                               for m in entry.get("mappings", ())),
                needs=tuple(entry["needs"]), optional_feature=entry.get("optional_feature", ""),
                judge=entry["judge"], phase=entry.get("phase", 1), remediation=entry.get("remediation", {}),
            )
        except (KeyError, ValueError) as e:
            raise CatalogError(f"{cid}: {e}") from None
    return controls, declared


CONTROLS, DECLARED_PREDICATES = load()
# Every framework some control maps to, in the order the file first names them
FRAMEWORKS: tuple[str, ...] = tuple(dict.fromkeys(m.framework for c in CONTROLS.values() for m in c.mappings))
