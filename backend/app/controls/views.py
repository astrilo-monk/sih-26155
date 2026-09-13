"""
Views of control results.

A Finding is the user-facing view of one FAIL result: the rule's failure
details plus the control's title, category and framework mappings from the
catalog. The API and frontend keep consuming Findings unchanged.
"""

from __future__ import annotations

from app.controls.catalog import CONTROLS, Control
from app.models.findings import ComplianceMapping, Finding
from app.models.results import ControlResult, Status


def compliance_for(control: Control, vendor: str) -> list[ComplianceMapping]:
    """Framework mappings that apply to ``vendor``: vendor-neutral ones plus its own benchmark items."""
    return [
        ComplianceMapping(m.framework, m.requirement_id, m.title, m.version)
        for m in control.mappings
        if m.vendor is None or m.vendor.value == vendor
    ]


def finding_from_result(result: ControlResult) -> Finding:
    if result.status != Status.FAIL or result.failure is None:
        raise ValueError(f"Only FAIL results have a Finding view (got {result.status.value} for {result.control_id})")
    control = CONTROLS[result.control_id]
    failure = result.failure
    return Finding(
        rule_id=control.control_id,
        title=control.title,
        severity=failure.severity,
        description=failure.description,
        device_hostname=result.device_hostname,
        vendor=result.vendor,
        evidence_lines=[f"  {n}: {text}" for n, text in zip(result.evidence.line_numbers, result.evidence.text)],
        line_numbers=list(result.evidence.line_numbers),
        security_impact=failure.security_impact,
        recommendation=failure.recommendation,
        compliance=compliance_for(control, result.vendor),
        category=control.category,
    )
