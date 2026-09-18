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
    # AI judge requests sent for this config, and blocks answered from the judge cache (Phase 7)
    ai_calls: int = 0
    ai_cache_hits: int = 0
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
    # parser | confirmed | default | heuristic (decided results) | ai_verified (UNKNOWN results with a proposal)
    assurance: Optional[str] = None
    # the AI's verdict (pass | fail) awaiting human confirmation; never scored
    proposed_status: Optional[str] = None
    device_hostname: str
    vendor: str
    scope: Optional[str] = None
    reason: str
    evidence: EvidenceSchema


class FrameworkControlSchema(BaseModel):
    """One mapped control's result on one device, as scanned (no re-evaluation)."""
    control_id: str
    title: str
    config_index: int
    device_hostname: str
    status: str
    assurance: Optional[str] = None
    proposed_status: Optional[str] = None
    # heuristic / AI verdict involved: never decisive
    provisional: bool = False
    decisive: bool = False
    outcome: str
    reason: str
    evidence: EvidenceSchema


class FrameworkRequirementSchema(BaseModel):
    requirement_id: str
    title: str
    # pass | fail | partial | unknown | not_configured | n_a
    status: str
    provisional: bool = False
    controls: list[FrameworkControlSchema]


class FrameworkViewSchema(BaseModel):
    """Control results regrouped by one framework version (mapped device-configuration controls only)."""
    framework: str
    version: str
    # share of applicable requirements decided PASS or FAIL on decisive evidence
    coverage: int
    counts: dict[str, int]
    requirements: list[FrameworkRequirementSchema]


class FindingSchema(BaseModel):
    rule_id: str
    title: str
    severity: str
    description: str
    device_hostname: str
    vendor: str
    # The uploaded config this finding belongs to: the identity (hostnames can repeat)
    config_index: int = 0
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
    # The same results regrouped by framework requirement (NIST SP 800-53, CIS for confirmed vendors)
    frameworks: list[FrameworkViewSchema] = []
    # Uploaded files holding no recognizable configuration at all: they are reported, never scored
    unreadable_configs: list[int] = []
    # Controls that decided PASS or FAIL from decisive evidence, and the applicable ones that did not
    assessed_count: int = 0
    unresolved_count: int = 0


class RemediationRequest(BaseModel):
    scan_id: str
    rule_id: str
    device_hostname: str
    # Picks the config when several uploads share a hostname
    config_index: Optional[int] = None
    # Operator values a recipe may need (syslog_server, ntp_server, ntp_key_id, ntp_key, management_subnet).
    # Validated and written only into fixed templates; there is no field for command text.
    inputs: dict[str, str] = {}


class RemediationInputSchema(BaseModel):
    name: str
    label: str
    help: str


class RemediationCheckSchema(BaseModel):
    # vendor | parse_coverage | target | no_regression | controls
    name: str
    passed: bool
    detail: str


class PostureSummarySchema(BaseModel):
    posture: Optional[int] = None
    coverage: int = 0
    posture_bounds: Optional[list[int]] = None
    critical_unassessed: list[str] = []
    # confirmed | unverified | unknown
    vendor_status: str
    parse_coverage: Optional[float] = None
    uncovered_lines: int = 0


class RemediationResponse(BaseModel):
    rule_id: str
    title: str
    device_hostname: str
    vendor: str
    config_index: int = 0
    # fixed | needs_input | manual_review | verification_failed | no_recipe | vendor_unverified | provisional | not_failing
    status: str
    reason: str
    explanation: str = ""
    warnings: list[str] = []
    scopes: list[str] = []
    # Before state: the lines the decisive FAIL results cite
    evidence: EvidenceSchema = EvidenceSchema()
    required_inputs: list[RemediationInputSchema] = []
    missing_inputs: list[str] = []
    control_status_before: Optional[str] = None
    control_status_after: Optional[str] = None
    # Proposed deterministic change (unified diff of the configuration)
    diff: str = ""
    checks: list[RemediationCheckSchema] = []
    before: Optional[PostureSummarySchema] = None
    after: Optional[PostureSummarySchema] = None
    # After state: the generated configuration (also kept when verification failed, for review)
    fixed_config: Optional[str] = None


class RemediationCandidateRequest(BaseModel):
    scan_id: str
    rule_id: str
    device_hostname: str
    # Picks the config when several uploads share a hostname
    config_index: Optional[int] = None
    # The command the administrator proposes. Required for a manual candidate, ignored elsewhere:
    # it is never executed and never written into a configuration NetAuditAI hands out.
    command: Optional[str] = None
    # Why an administrator rejected the candidate (reject only)
    reason: Optional[str] = None


class RemediationCandidateSchema(BaseModel):
    config_index: int
    rule_id: str
    title: str
    device_hostname: str
    vendor: str
    # confirmed | unverified | unknown — a candidate exists only for the last two
    vendor_status: str
    # manual | ai
    source: str
    # draft | verified | unverified | rejected | confirmed
    status: str
    command: str
    reason: str
    explanation: str = ""
    # low | medium | high (AI candidates only)
    confidence: str = ""
    assumptions: list[str] = []
    # The failing lines the candidate has to address
    evidence: EvidenceSchema = EvidenceSchema()
    control_status_before: Optional[str] = None
    control_status_after: Optional[str] = None
    # target | no_regression | generic_path
    checks: list[RemediationCheckSchema] = []
    # The simulated change on a copy of the uploaded configuration (never a device change)
    diff: str = ""
    # Whether POST /remediation/candidate/download can hand out the verified corrected copy. The copy
    # itself is never sent in this schema: only the endpoint returns configuration text.
    download_available: bool = False
    created_at: str = ""
    confirmed_at: Optional[str] = None


class RemediationPlanRequest(BaseModel):
    scan_id: str
    inputs: dict[str, str] = {}


class DeviceRemediationPlanSchema(BaseModel):
    config_index: int
    device_hostname: str
    vendor: str
    vendor_status: str
    remediations: list[RemediationResponse]
    # Candidate remediations proposed for this device in this scan (unconfirmed vendors only)
    candidates: list[RemediationCandidateSchema] = []
    fixed_controls: list[str] = []
    checks: list[RemediationCheckSchema] = []
    before: Optional[PostureSummarySchema] = None
    after: Optional[PostureSummarySchema] = None
    # Every verified change applied in sequence; None when nothing was fixed
    fixed_config: Optional[str] = None


class RemediationPlanResponse(BaseModel):
    scan_id: str
    inputs: list[RemediationInputSchema]
    devices: list[DeviceRemediationPlanSchema]


class AssistantRequest(BaseModel):
    scan_id: str
    message: str


class AssistantResponse(BaseModel):
    response: str
    scan_id: str


class DownloadFixedRequest(BaseModel):
    scan_id: str
    inputs: dict[str, str] = {}


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
    # "seed" = shipped knowledge, "runtime" = confirmed by an administrator on this deployment
    source: str = "runtime"


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


class TeachLineSchema(BaseModel):
    """A line an administrator may be asked about for one undecided control."""
    line_number: int
    text: str
    scope_path: list[str] = []
    # The reading a heuristic (or a verified AI proposal) already has for this line, when there is one
    predicate: Optional[str] = None
    subject: Optional[str] = None
    value: Any = None


class MeaningOptionSchema(BaseModel):
    """Something an administrator may say a line means. A value setting is read from the line, not stated here."""
    predicate: str
    subject: Optional[str] = None
    value: Any = None


class UnresolvedControlSchema(BaseModel):
    config_index: int
    hostname: str
    control_id: str
    title: str
    question: str
    severity: str
    category: str
    # unknown | not_configured
    status: str
    # Why the engine could not decide it
    reason: str
    # The configuration it did cite, if any
    evidence_lines: list[int] = []
    evidence: list[str] = []
    # teach = a line can be taught here; blocked = a confirmed vendor parser reads this config
    action: str
    needs: list[str] = []
    suggested_lines: list[TeachLineSchema] = []
    blocked_reason: Optional[str] = None


class UnresolvedQueueResponse(BaseModel):
    scan_id: str
    # Applicable controls that decided PASS or FAIL from decisive evidence, and the rest
    assessed_count: int
    unresolved_count: int
    items: list[UnresolvedControlSchema]


class ConfigLineSchema(BaseModel):
    line_number: int
    text: str
    # A tokenizer statement a recognizer could be taught from
    teachable: bool


class ConfigTextResponse(BaseModel):
    config_index: int
    hostname: str
    vendor: str
    lines: list[ConfigLineSchema]


class MeaningOptionsResponse(BaseModel):
    control_id: str
    line_number: int
    text: str
    options: list[MeaningOptionSchema]


class RecognizerDraftRequest(BaseModel):
    config_index: int = 0
    control_id: str
    line_number: int
    # An administrator's answer for a line no heuristic read: what this line says about the control.
    # The predicate must be one the control needs; the line must still state the value.
    predicate: Optional[str] = None
    asserted_value: Optional[Any] = None
    subject: Optional[str] = None
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
