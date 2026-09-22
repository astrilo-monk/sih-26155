"""
Framework views (Phase 9): control results regrouped by framework requirement.

Nothing is evaluated here. Each requirement lists the catalog controls mapped to it
(``controls/catalog.py``, exact framework version) and their results as scanned:

* FAIL           any mapped control FAILs on decisive evidence
* PASS           every applicable mapped control PASSes on decisive evidence
* PARTIAL        some mapped controls PASS decisively, the others are undecided
* NOT_CONFIGURED every mapped control is NOT_CONFIGURED
* UNKNOWN        otherwise (undecided, or only heuristic / AI proposals)
* N_A            every mapped control is N/A

Heuristic and AI_VERIFIED verdicts are never decisive: a requirement they touch is marked
``provisional`` and cannot PASS or FAIL on them. Product benchmarks (CIS) apply only to
devices whose vendor profile is confirmed; unknown vendors see vendor-neutral mappings.
A framework view reports mapped device-configuration controls -it is not a compliance
certification.
"""

from __future__ import annotations

from app.analysis.scoring import _control_outcome
from app.controls.catalog import CONTROLS
from app.models.results import Assurance, ControlResult, Status

PROVISIONAL_ASSURANCE = frozenset({Assurance.HEURISTIC, Assurance.AI_VERIFIED})
STATUSES = ("pass", "fail", "partial", "unknown", "not_configured", "n_a")


def _requirement_status(entries: list[dict]) -> str:
    outcomes = [e["outcome"] for e in entries]
    if "fail" in outcomes:
        return "fail"
    applicable = [e for e in entries if e["outcome"] != "n_a"]
    if not applicable:
        return "n_a"
    if all(e["outcome"] == "pass" for e in applicable):
        return "pass"
    if any(e["outcome"] == "pass" for e in applicable):
        return "partial"
    if all(e["status"] == Status.NOT_CONFIGURED.value for e in applicable):
        return "not_configured"
    return "unknown"


def _entry(config_index: int, group: list[ControlResult]) -> dict:
    control = CONTROLS[group[0].control_id]
    outcome, _ = _control_outcome(group)
    fails = [r for r in group if r.status == Status.FAIL]
    shown = fails or group
    numbers, lines = [], []
    for r in shown:
        for n, text in zip(r.evidence.line_numbers, r.evidence.text):
            if n not in numbers:
                numbers.append(n)
                lines.append(text)
    return dict(
        control_id=control.control_id,
        title=control.title,
        config_index=config_index,
        device_hostname=group[0].device_hostname,
        status=shown[0].status.value,
        assurance=shown[0].assurance.value if shown[0].assurance else None,
        proposed_status=next((r.proposed_status.value for r in group if r.proposed_status), None),
        provisional=any(r.assurance in PROVISIONAL_ASSURANCE or r.proposed_status for r in group),
        decisive=outcome in ("pass", "fail"),
        outcome=outcome,
        reason="; ".join(dict.fromkeys(r.reason for r in shown)),
        evidence=dict(line_numbers=numbers, lines=lines),
    )


def framework_views(device_results: list[list[ControlResult]]) -> list[dict]:
    requirements: dict[tuple[str, str], dict[str, dict]] = {}
    for config_index, results in enumerate(device_results):
        by_control: dict[str, list[ControlResult]] = {}
        for r in results:
            by_control.setdefault(r.control_id, []).append(r)
        for control_id, group in by_control.items():
            entry = _entry(config_index, group)
            for mapping in CONTROLS[control_id].mappings:
                if mapping.vendor is not None and mapping.vendor.value != group[0].vendor:
                    continue
                requirement = requirements.setdefault((mapping.framework, mapping.version), {}).setdefault(
                    mapping.requirement_id,
                    dict(requirement_id=mapping.requirement_id, title=mapping.title, controls=[]),
                )
                requirement["controls"].append(entry)

    views = []
    for (framework, version), by_id in sorted(requirements.items()):
        rows = []
        for requirement in sorted(by_id.values(), key=lambda r: r["requirement_id"]):
            status = _requirement_status(requirement["controls"])
            rows.append(dict(requirement, status=status,
                             provisional=any(e["provisional"] for e in requirement["controls"])))
        applicable = [r for r in rows if r["status"] != "n_a"]
        decided = [r for r in applicable if r["status"] in ("pass", "fail")]
        views.append(dict(
            framework=framework,
            version=version,
            coverage=round(len(decided) * 100 / len(applicable)) if applicable else 0,
            counts={s: sum(r["status"] == s for r in rows) for s in STATUSES},
            requirements=rows,
        ))
    return views
