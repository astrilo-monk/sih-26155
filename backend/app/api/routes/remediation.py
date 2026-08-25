"""
Remediation API routes.

Generates vendor-specific fix commands for findings and
supports before/after verification by re-analyzing a
patched config copy.
"""

from __future__ import annotations
from fastapi import APIRouter, HTTPException
from app.api.schemas import RemediationRequest, RemediationResponse, VerifyRequest, VerifyResponse, FindingSchema, ComplianceMappingSchema
from app.api.routes.scan import get_scan_store
from app.parsers.detector import detect_vendor
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.fortinet import FortinetParser
from app.analysis.engine import analyze
from app.models.normalized import Vendor
from app.remediation.engine import generate_remediation, apply_remediation

router = APIRouter()


@router.post("/remediate", response_model=RemediationResponse)
async def remediate_finding(req: RemediationRequest):
    """Generate a fix for a specific finding."""
    store = get_scan_store()
    stored = store.get(req.scan_id)
    if not stored:
        raise HTTPException(404, "Scan not found")

    result = stored["result"]

    # Find the specific finding
    finding = None
    for f in result.findings:
        if f.rule_id == req.rule_id and f.device_hostname == req.device_hostname:
            finding = f
            break

    if not finding:
        raise HTTPException(404, "Finding not found in scan results")

    remediation = generate_remediation(finding, stored["configs"])

    return RemediationResponse(
        rule_id=finding.rule_id,
        title=finding.title,
        device_hostname=finding.device_hostname,
        vendor=finding.vendor,
        original_lines=finding.evidence_lines,
        remediation_commands=remediation["commands"],
        explanation=remediation["explanation"],
    )


@router.post("/verify", response_model=VerifyResponse)
async def verify_remediation(req: VerifyRequest):
    """
    Apply remediation to a copy of the config and re-analyze.
    Shows before/after comparison.
    """
    store = get_scan_store()
    stored = store.get(req.scan_id)
    if not stored:
        raise HTTPException(404, "Scan not found")

    original_result = stored["result"]
    configs = stored["configs"]

    if not configs:
        raise HTTPException(400, "No configs available for verification")

    # Apply remediation to a copy and re-analyze
    modified_config = apply_remediation(configs[0], req.remediation_commands)

    new_result = analyze(modified_config)

    resolved = []
    new_rule_ids = {f.rule_id for f in new_result.findings}
    for f in original_result.findings:
        if f.rule_id not in new_rule_ids:
            resolved.append(f.title)

    return VerifyResponse(
        original_score=original_result.score,
        new_score=new_result.score,
        original_findings=original_result.total_findings,
        new_findings=new_result.total_findings,
        original_critical=original_result.critical_count,
        new_critical=new_result.critical_count,
        resolved_findings=resolved,
        remaining_findings=[
            FindingSchema(
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity.value,
                description=f.description,
                device_hostname=f.device_hostname,
                vendor=f.vendor,
                evidence_lines=f.evidence_lines,
                line_numbers=f.line_numbers,
                security_impact=f.security_impact,
                recommendation=f.recommendation,
                compliance=[
                    ComplianceMappingSchema(
                        framework=c.framework,
                        control_id=c.control_id,
                        description=c.description,
                    ) for c in f.compliance
                ],
                ai_explanation=f.ai_explanation,
                category=f.category,
            ) for f in new_result.findings
        ],
    )
