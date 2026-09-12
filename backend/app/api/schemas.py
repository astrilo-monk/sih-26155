"""
Pydantic schemas for API request/response validation.
"""

from __future__ import annotations
from pydantic import BaseModel
from typing import Optional


class AdaptiveLineSchema(BaseModel):
    """A security-relevant unrecognized line captured during parsing."""
    line_number: int
    raw_line: str
    vendor: str
    context_before: list[str] = []
    context_after: list[str] = []


class AdaptiveInterpretationSchema(BaseModel):
    """AI interpretation result for a single configuration line (display-only)."""
    line_number: int
    raw_line: str
    likely_vendor: str
    security_concept: str
    normalized_field: str
    extracted_value: Optional[str] = None
    confidence: str
    reasoning: str
    status: str


class AdaptiveScanInfoSchema(BaseModel):
    """Adaptive interpretation summary for an unknown-vendor scan."""
    ai_available: bool
    unrecognized_lines: list[AdaptiveLineSchema]
    interpretations: list[AdaptiveInterpretationSchema]


class ScanSummaryResponse(BaseModel):
    scan_id: str
    timestamp: str
    score: Optional[int] = None
    total_findings: Optional[int] = None
    critical: Optional[int] = None
    high: Optional[int] = None
    medium: Optional[int] = None
    low: Optional[int] = None
    devices: list[dict]


class ComplianceMappingSchema(BaseModel):
    framework: str
    control_id: str
    description: str = ""


class FindingSchema(BaseModel):
    rule_id: str
    title: str
    severity: str
    description: str
    device_hostname: str
    vendor: str
    evidence_lines: list[str]
    line_numbers: list[int]
    security_impact: str
    recommendation: str
    compliance: list[ComplianceMappingSchema]
    ai_explanation: Optional[str] = None
    category: str


class ScanResultResponse(BaseModel):
    scan_id: str
    timestamp: str
    score: Optional[int] = None
    total_findings: Optional[int] = None
    critical: Optional[int] = None
    high: Optional[int] = None
    medium: Optional[int] = None
    low: Optional[int] = None
    devices: list[dict]
    findings: list[FindingSchema] = []
    # Adaptive interpretation results (populated for unknown-vendor configs;
    # display-only — NOT consumed by the deterministic compliance engine)
    adaptive: Optional[AdaptiveScanInfoSchema] = None


class RemediationRequest(BaseModel):
    scan_id: str
    rule_id: str
    device_hostname: str


class RemediationResponse(BaseModel):
    rule_id: str
    title: str
    device_hostname: str
    vendor: str
    original_lines: list[str]
    remediation_commands: str
    explanation: str


class VerifyRequest(BaseModel):
    scan_id: str
    remediation_commands: str


class VerifyResponse(BaseModel):
    original_score: int
    new_score: int
    original_findings: int
    new_findings: int
    original_critical: int
    new_critical: int
    resolved_findings: list[str]
    remaining_findings: list[FindingSchema]


class AssistantRequest(BaseModel):
    scan_id: str
    message: str


class AssistantResponse(BaseModel):
    response: str
    scan_id: str


class DownloadFixedRequest(BaseModel):
    scan_id: str
