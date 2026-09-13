"""
Pydantic schemas for API request/response validation.
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any, Optional


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
    # False when no rule could evaluate real evidence from this config
    assessed: bool = True


class VendorIdentificationSchema(BaseModel):
    """Deterministic vendor identification for one config — never from AI output."""
    config_index: int
    # What the fingerprint detector matched
    detected_vendor: str
    # confirmed | unverified (resembles the vendor, grammar coverage too low) | unknown
    status: str
    # Share of meaningful lines that follow the detected vendor's grammar
    parse_coverage: Optional[float] = None
    uncovered_lines: int = 0
    # Why an unverified profile was rejected
    reason: Optional[str] = None


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
    version: str = ""


class EvidenceSchema(BaseModel):
    line_numbers: list[int] = []
    lines: list[str] = []
    scope_path: list[str] = []


class ControlResultSchema(BaseModel):
    """The answer to one control for one uploaded config."""
    config_index: int
    control_id: str
    title: str
    question: str
    kind: str
    category: str
    severity: str
    # pass | fail | not_configured | unknown | n_a
    status: str
    # parser | confirmed | default | heuristic | ai_verified (decided results only)
    assurance: Optional[str] = None
    proposed_status: Optional[str] = None
    device_hostname: str
    vendor: str
    scope: Optional[str] = None
    reason: str
    evidence: EvidenceSchema


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
    # heuristic / ai_verified: a suspected FAIL, not scored until confirmed
    assurance: Optional[str] = None


class ScanResultResponse(BaseModel):
    scan_id: str
    timestamp: str
    # DEPRECATED (Phase 3): legacy 100 - penalties score; use posture + coverage
    score: Optional[int] = None
    # Weighted PASS / (PASS + FAIL) over decisive results; None when nothing was decided
    posture: Optional[int] = None
    # Weighted share (0-100) of applicable controls that were decisively decided
    coverage: int = 0
    # [posture if all undecided controls fail, posture if they all pass]
    posture_bounds: Optional[list[int]] = None
    # Critical controls that could not be decisively assessed
    critical_unassessed: list[str] = []
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
    # One entry per uploaded config, in upload order
    vendor_identification: list[VendorIdentificationSchema] = []
    # Every control's result for every config (findings are the FAIL results)
    results: list[ControlResultSchema] = []


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
    original_score: Optional[int] = None
    new_score: Optional[int] = None
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
    predicate: Optional[str] = None
    subject: Optional[str] = None
    scope_template: Optional[str] = None
    dialect_fingerprint: Optional[str] = None
    negatives: list[str] = []


# ── Recognizers (Phase 6) ────────────────────────────────────────────────────

class ProvisionalLineSchema(BaseModel):
    """A statement a heuristic read for a control; confirming it drafts a recognizer."""
    line_number: int
    text: str
    predicate: str
    subject: Optional[str] = None
    value: Any = None


class ProvisionalItemSchema(BaseModel):
    config_index: int
    control_id: str
    question: str
    status: str
    assurance: Optional[str] = None
    reason: str
    lines: list[ProvisionalLineSchema]


class ProvisionalQueueResponse(BaseModel):
    scan_id: str
    items: list[ProvisionalItemSchema]


class RecognizerDraftRequest(BaseModel):
    config_index: int = 0
    control_id: str
    line_number: int
    # Admin edits of the draft (None keeps the drafted value)
    command_pattern: Optional[str] = None
    scope_template: Optional[str] = None
    # JSON: a constant, or an {enum:name} value table
    value: Optional[str] = None
    any_dialect: bool = False
    negatives: list[str] = []


class RecognizerDraftSchema(BaseModel):
    concept: str
    predicate: str
    subject: Optional[str] = None
    command_pattern: str
    scope_template: Optional[str] = None
    value: Optional[str] = None
    dialect_fingerprint: Optional[str] = None
    example_line: str
    negatives: list[str] = []


class ReplayChangeSchema(BaseModel):
    hostname: str
    control_id: str
    before: str
    after: str


class RecognizerDraftResponse(BaseModel):
    draft: RecognizerDraftSchema
    # Failed safety gates; empty when the recognizer can be saved
    errors: list[str] = []
    # Replay against stored configs: results the recognizer would change
    configs_checked: int = 0
    replay: list[ReplayChangeSchema] = []


class RecognizerSaveResponse(BaseModel):
    mapping: LearnedMappingSchema
    replay: list[ReplayChangeSchema] = []
    scan: ScanResultResponse


class RejectProvisionalRequest(BaseModel):
    config_index: int = 0
    control_id: str
    line_number: int
    reason: Optional[str] = None


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
