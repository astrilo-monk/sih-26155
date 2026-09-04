"""
Pydantic schemas for API request/response validation.
"""

from __future__ import annotations
from pydantic import BaseModel
from typing import Optional


class ScanSummaryResponse(BaseModel):
    scan_id: str
    timestamp: str
    score: int
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
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
    score: int
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    devices: list[dict]
    findings: list[FindingSchema]


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
