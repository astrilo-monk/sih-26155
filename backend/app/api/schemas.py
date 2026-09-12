"""
Pydantic schemas for API request/response validation.
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional


class AdaptiveLineSchema(BaseModel):
    """A security-relevant unrecognized line captured during parsing."""
    line_number: int
    raw_line: str
    vendor: str
    context_before: list[str] = []
    context_after: list[str] = []
    structural_path: list[str] = []


class AdaptiveInterpretationSchema(BaseModel):
    """AI interpretation result for a single configuration line (display-only)."""
    line_number: int
    raw_line: str
    likely_vendor: str
    security_concept: str
    normalized_field: str
    extracted_value: Optional[str] = None
    value_evidence: Optional[str] = None
    confidence: str
    numeric_confidence: Optional[float] = None
    confidence_tier: Optional[str] = None
    reasoning: str
    status: str
    # Phase 3 disposition: ai_auto_mapped, needs_review, needs_training
    source: Optional[str] = None


class AIFieldMappingSchema(BaseModel):
    """Audit record for one adaptive line's effect on NormalizedConfig."""
    line_number: int
    raw_line: str
    normalized_field: str
    extracted_value: Optional[str] = None
    confidence: float
    confidence_tier: str
    reasoning: str
    # ai_auto_mapped, learned_mapping, admin_confirmed, needs_review,
    # needs_training, rejected
    source: str
    status: str
    likely_vendor: str = ""
    security_concept: str = ""
    final_value: Optional[str] = None
    mapping_id: Optional[int] = None
    reason: str = ""


class VendorEvidenceSchema(BaseModel):
    """What adaptive interpretations suggest about the vendor — reporting only.

    Never used to select vendor-specific rules; ``devices[].vendor`` comes
    from the deterministic detector alone.
    """
    likely_vendor: str = "unknown"
    # identified | conflicting | unknown
    status: str = "unknown"
    supporting_lines: list[int] = []
    votes: dict[str, int] = {}


class AdaptiveScanInfoSchema(BaseModel):
    """Adaptive enrichment summary for one scanned config."""
    ai_available: bool
    unrecognized_lines: list[AdaptiveLineSchema]
    interpretations: list[AdaptiveInterpretationSchema]
    ai_mappings: list[AIFieldMappingSchema] = []
    config_index: int = 0
    hostname: str = "unknown"
    vendor: str = "unknown"
    # Whether the AI interpreter was actually called for this config
    ai_called: bool = False
    # Lines resolved by confirmed learned mappings (no AI involved)
    learned_matches: int = 0
    # Lines awaiting administrator review / training
    pending_review: int = 0
    # True when the score cannot be read as a full compliance verdict
    score_provisional: bool = False
    provisional_reasons: list[str] = []
    # Vendor evidence from adaptive interpretations (reporting only)
    vendor_evidence: Optional[VendorEvidenceSchema] = None
    # Lines the AI could not assess (outage / quota) — distinct from low confidence
    ai_unavailable_lines: int = 0


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
    # Adaptive enrichment for the first config that went through the adaptive
    # layer (kept for backwards compatibility) and for every such config.
    adaptive: Optional[AdaptiveScanInfoSchema] = None
    adaptive_configs: list[AdaptiveScanInfoSchema] = []


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


# ── Adaptive training (Phase 4/5) ─────────────────────────────────────────────

class NormalizedFieldSchema(BaseModel):
    field: str
    value_type: str
    label: str = ""
    description: str = ""
    value_rule: str = ""


class LearnedMappingSchema(BaseModel):
    id: int
    concept: str
    normalized_field: str
    vendor: Optional[str] = None
    command_pattern: str
    extraction_method: str
    expected_value_type: str
    constant_value: Optional[str] = None
    confidence: float
    confirmed: bool
    active: bool
    example_line: Optional[str] = None
    created_at: str
    updated_at: str


class CandidateMappingSchema(BaseModel):
    """A learned mapping that resembles a line (possibly from another vendor)."""
    mapping: LearnedMappingSchema
    score: float


class ReviewItemSchema(BaseModel):
    item_id: str
    config_index: int
    hostname: str
    vendor: str
    line_number: int
    raw_line: str
    context_before: list[str] = []
    context_after: list[str] = []
    structural_path: list[str] = []
    # AI suggestion
    likely_vendor: str = ""
    security_concept: str = ""
    normalized_field: str
    extracted_value: Optional[str] = None
    confidence: float
    confidence_tier: str
    reasoning: str
    interpretation_status: str
    # Disposition
    source: str
    reason: str = ""
    review_status: str  # pending, accepted, edited, rejected, learned
    mapping_id: Optional[int] = None
    candidates: list[CandidateMappingSchema] = []


class ReviewQueueResponse(BaseModel):
    scan_id: str
    pending_count: int
    items: list[ReviewItemSchema]


class AcceptInterpretationRequest(BaseModel):
    concept: Optional[str] = None
    command_pattern: Optional[str] = None


class EditInterpretationRequest(BaseModel):
    normalized_field: str = Field(..., min_length=1)
    extracted_value: str = Field(..., min_length=1)
    concept: Optional[str] = None
    command_pattern: Optional[str] = None


class RejectInterpretationRequest(BaseModel):
    reason: Optional[str] = None


class ReviewActionResponse(BaseModel):
    item: ReviewItemSchema
    mapping: Optional[LearnedMappingSchema] = None
    # Other pending lines in the same scan resolved by the new mapping
    auto_resolved: list[str] = []
    scan: ScanResultResponse


class MappingUpdateRequest(BaseModel):
    concept: Optional[str] = None
    normalized_field: Optional[str] = None
    vendor: Optional[str] = None
    command_pattern: Optional[str] = None
    extraction_method: Optional[str] = None
    constant_value: Optional[str] = None
    active: Optional[bool] = None
