"""
Adaptive training API (Phase 4) and learned mapping management (Phase 5).

The frontend talks only to these endpoints; it never sees the AI provider,
its request format, or the SQLite store.

Review flow for a line the adaptive layer could not safely apply:

    accept / edit → validate field + value → persist confirmed learned mapping
                  → apply to the stored config → re-run deterministic engine
    reject        → remember the line as reviewed-but-unmapped so future scans
                    do not send it to the AI again
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, HTTPException

from app.adaptive.mapper import (
    FIELD_REGISTRY,
    REVIEWABLE_SOURCES,
    SOURCE_LEARNED_MAPPING,
    SOURCE_REJECTED,
    AdaptiveMapper,
    InterpretationValidator,
)
from app.adaptive.matcher import (
    EXTRACTION_CONSTANT,
    EXTRACTION_RECOGNIZER,
    EXTRACTION_TEMPLATE_CAPTURE,
    VALUE_TOKEN,
    LearnedMappingMatcher,
    PatternError,
    derive_pattern,
    match_pattern,
)
from app.adaptive.vendor import UNKNOWN_VENDOR, normalize_vendor_name
from app.analysis.engine import evaluate_controls
from app.api.routes.scan import (
    _device_results,
    build_scan_response,
    get_scan_store,
    reanalyze_scan,
)
from app.api.schemas import (
    AcceptInterpretationRequest,
    CandidateMappingSchema,
    EditInterpretationRequest,
    LearnedMappingSchema,
    MappingUpdateRequest,
    NormalizedFieldSchema,
    ProvisionalItemSchema,
    ProvisionalLineSchema,
    ProvisionalQueueResponse,
    RecognizerDraftRequest,
    RecognizerDraftResponse,
    RecognizerDraftSchema,
    RecognizerSaveResponse,
    RejectInterpretationRequest,
    RejectProvisionalRequest,
    ReplayChangeSchema,
    ReviewActionResponse,
    ReviewItemSchema,
    ReviewQueueResponse,
    ScanResultResponse,
)
from app.controls.catalog import CONTROLS
from app.db.mappings import (
    ADMIN_ACTOR,
    LearnedMapping,
    MappingConflictError,
    MappingNotFoundError,
    MappingPermissionError,
    MappingRepository,
    MappingValidationError,
    validate_mapping,
)
from app.facts.heuristics import _Candidate
from app.facts.recognizers import draft_recognizer, provisional_lines
from app.models.normalized import AIFieldMapping, NormalizedConfig, Vendor
from app.models.results import DECISIVE_ASSURANCE, ControlResult, Status

router = APIRouter(prefix="/adaptive")


def _repository() -> MappingRepository:
    return MappingRepository()


def _mapping_schema(m: LearnedMapping) -> LearnedMappingSchema:
    return LearnedMappingSchema(**asdict(m))


# ── Review queue helpers ──────────────────────────────────────────────────────

def _get_entry(scan_id: str) -> dict:
    entry = get_scan_store().get(scan_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    return entry


def _item_id(config_index: int, line_number: int) -> str:
    return f"{config_index}-{line_number}"


def _build_item(entry: dict, config_index: int, record: AIFieldMapping) -> ReviewItemSchema:
    config: NormalizedConfig = entry["configs"][config_index]
    item_id = _item_id(config_index, record.line_number)
    line = next((ln for ln in config.unrecognized_lines if ln.line_number == record.line_number), None)
    run = entry["adaptive_runs"][config_index] or {}
    state = entry["review_state"].get(item_id)

    return ReviewItemSchema(
        item_id=item_id,
        config_index=config_index,
        hostname=config.device.hostname,
        vendor=config.device.vendor.value,
        line_number=record.line_number,
        raw_line=record.raw_line,
        context_before=list(line.context_before) if line else [],
        context_after=list(line.context_after) if line else [],
        structural_path=list(line.structural_path) if line else [],
        likely_vendor=record.likely_vendor,
        security_concept=record.security_concept,
        normalized_field=record.normalized_field,
        extracted_value=record.extracted_value,
        confidence=record.confidence,
        confidence_tier=record.confidence_tier,
        reasoning=record.reasoning,
        interpretation_status=record.status,
        source=record.source,
        reason=record.reason,
        review_status=state["status"] if state else "pending",
        mapping_id=record.mapping_id,
        candidates=[
            CandidateMappingSchema(mapping=_mapping_schema(c.mapping), score=c.score)
            for c in run.get("candidates", {}).get(record.line_number, [])
        ],
    )


def _find_record(entry: dict, item_id: str) -> tuple[int, int, AIFieldMapping]:
    """Resolve an item id to (config_index, record_index, record)."""
    try:
        config_index, line_number = (int(part) for part in item_id.split("-", 1))
        config: NormalizedConfig = entry["configs"][config_index]
    except (ValueError, IndexError):
        raise HTTPException(404, "Review item not found")

    for record_index, record in enumerate(config.ai_mappings):
        if record.line_number == line_number:
            return config_index, record_index, record
    raise HTTPException(404, "Review item not found")


def _pending_record(entry: dict, item_id: str) -> tuple[int, int, AIFieldMapping]:
    config_index, record_index, record = _find_record(entry, item_id)
    state = entry["review_state"].get(item_id)
    if state is not None or record.source not in REVIEWABLE_SOURCES:
        status = state["status"] if state else record.source
        raise HTTPException(409, f"Item has already been reviewed ({status})")
    return config_index, record_index, record


def _mapping_vendor(config: NormalizedConfig, record: AIFieldMapping) -> Optional[str]:
    if config.device.vendor != Vendor.UNKNOWN:
        return config.device.vendor.value
    vendor = normalize_vendor_name(record.likely_vendor)
    return None if vendor == UNKNOWN_VENDOR else vendor


def _resolve_pattern(raw_line: str, value: str, command_pattern: Optional[str]) -> tuple[str, str]:
    """Pick or validate the command pattern for a confirmed line."""
    if not command_pattern or not command_pattern.strip():
        return derive_pattern(raw_line, value)

    method = EXTRACTION_TEMPLATE_CAPTURE if VALUE_TOKEN in command_pattern else EXTRACTION_CONSTANT
    try:
        matched, captured = match_pattern(command_pattern, method, raw_line)
    except PatternError as e:
        raise HTTPException(422, f"Invalid command pattern: {e}")
    if not matched:
        raise HTTPException(422, "Command pattern does not match the original line")
    if method == EXTRACTION_TEMPLATE_CAPTURE and captured.strip().lower() != value.strip().lower():
        raise HTTPException(
            422, f"Command pattern captures '{captured}' but the extracted value is '{value}'"
        )
    return " ".join(command_pattern.split()), method


def _confirm(
    scan_id: str,
    item_id: str,
    normalized_field: str,
    extracted_value: str,
    concept: Optional[str],
    command_pattern: Optional[str],
    review_status: str,
) -> ReviewActionResponse:
    entry = _get_entry(scan_id)
    config_index, record_index, record = _pending_record(entry, item_id)
    config: NormalizedConfig = entry["configs"][config_index]

    normalized_field = normalized_field.strip()
    extracted_value = extracted_value.strip()
    validation = InterpretationValidator.validate_value(normalized_field, extracted_value)
    if not validation.is_valid:
        raise HTTPException(422, validation.reason)

    pattern, method = _resolve_pattern(record.raw_line, extracted_value, command_pattern)
    concept = (concept or "").strip() or (
        record.security_concept if record.security_concept not in ("", "unknown") else normalized_field
    )

    repository = _repository()
    try:
        saved = repository.save_mapping(
            LearnedMapping(
                concept=concept,
                normalized_field=normalized_field,
                vendor=_mapping_vendor(config, record),
                command_pattern=pattern,
                extraction_method=method,
                constant_value=extracted_value if method == EXTRACTION_CONSTANT else None,
                confidence=1.0,
                confirmed=True,
                example_line=record.raw_line.strip(),
            ),
            actor=ADMIN_ACTOR,
        )
    except MappingConflictError as e:
        raise HTTPException(409, str(e))
    except MappingValidationError as e:
        raise HTTPException(422, str(e))

    mapper = AdaptiveMapper()
    config.ai_mappings[record_index] = mapper.apply_admin(
        config, record, normalized_field, extracted_value, saved,
    )
    entry["review_state"][item_id] = {"status": review_status, "mapping_id": saved.id}

    auto_resolved = _apply_to_pending(entry, repository)
    reanalyze_scan(scan_id)

    return ReviewActionResponse(
        item=_build_item(entry, config_index, config.ai_mappings[record_index]),
        mapping=_mapping_schema(saved),
        auto_resolved=auto_resolved,
        scan=build_scan_response(scan_id),
    )


def _apply_to_pending(entry: dict, repository: MappingRepository) -> list[str]:
    """Let a newly confirmed mapping resolve other pending lines in the same scan."""
    matcher = LearnedMappingMatcher(repository)
    mapper = AdaptiveMapper()
    resolved = []

    for config_index, config in enumerate(entry["configs"]):
        lines = {ln.line_number: ln for ln in config.unrecognized_lines}
        for record_index, record in enumerate(config.ai_mappings):
            item_id = _item_id(config_index, record.line_number)
            if record.source not in REVIEWABLE_SOURCES or item_id in entry["review_state"]:
                continue
            line = lines.get(record.line_number)
            outcome = matcher.match_line(record.raw_line)
            if line is None or outcome.match is None:
                continue
            learned = mapper.apply_learned(config, line, outcome.match)
            if learned.source == SOURCE_LEARNED_MAPPING:
                config.ai_mappings[record_index] = learned
                entry["review_state"][item_id] = {"status": "learned", "mapping_id": learned.mapping_id}
                resolved.append(item_id)
    return resolved


# ── Endpoints: fields & review queue ─────────────────────────────────────────

@router.get("/fields", response_model=list[NormalizedFieldSchema])
async def list_normalized_fields():
    """Settable NormalizedConfig fields an interpretation may map to."""
    return [
        NormalizedFieldSchema(
            field=name,
            value_type=info.type_category,
            label=info.label,
            description=info.description,
            value_rule=info.value_rule,
        )
        for name, info in sorted(FIELD_REGISTRY.items())
    ]


@router.get("/scans/{scan_id}/review", response_model=ReviewQueueResponse)
async def list_review_items(scan_id: str, include_resolved: bool = False):
    """Unresolved interpretations for a scan (optionally with reviewed ones)."""
    entry = _get_entry(scan_id)
    items = []
    for config_index, config in enumerate(entry["configs"]):
        for record in config.ai_mappings:
            reviewed = _item_id(config_index, record.line_number) in entry["review_state"]
            pending = record.source in REVIEWABLE_SOURCES and not reviewed
            if pending or (include_resolved and reviewed):
                items.append(_build_item(entry, config_index, record))

    return ReviewQueueResponse(
        scan_id=scan_id,
        pending_count=sum(1 for i in items if i.review_status == "pending"),
        items=items,
    )


@router.post("/scans/{scan_id}/review/{item_id}/accept", response_model=ReviewActionResponse)
async def accept_interpretation(
    scan_id: str,
    item_id: str,
    body: Optional[AcceptInterpretationRequest] = None,
):
    """Accept the AI suggestion unchanged and persist it as a learned mapping."""
    entry = _get_entry(scan_id)
    _, _, record = _pending_record(entry, item_id)
    if record.normalized_field == "unknown" or record.extracted_value is None:
        raise HTTPException(
            422, "This interpretation has no usable field/value — edit it instead of accepting"
        )
    body = body or AcceptInterpretationRequest()
    return _confirm(
        scan_id, item_id, record.normalized_field, record.extracted_value,
        body.concept, body.command_pattern, review_status="accepted",
    )


@router.post("/scans/{scan_id}/review/{item_id}/edit", response_model=ReviewActionResponse)
async def edit_interpretation(scan_id: str, item_id: str, body: EditInterpretationRequest):
    """Accept an administrator-corrected interpretation and persist it."""
    return _confirm(
        scan_id, item_id, body.normalized_field, body.extracted_value,
        body.concept, body.command_pattern, review_status="edited",
    )


@router.post("/scans/{scan_id}/review/{item_id}/reject", response_model=ReviewActionResponse)
async def reject_interpretation(
    scan_id: str,
    item_id: str,
    body: Optional[RejectInterpretationRequest] = None,
):
    """Mark a line reviewed-but-unmapped; future scans will not send it to the AI."""
    entry = _get_entry(scan_id)
    config_index, record_index, record = _pending_record(entry, item_id)
    config: NormalizedConfig = entry["configs"][config_index]
    reason = (body.reason if body else None) or "Rejected by administrator"

    _repository().record_rejection(record.raw_line, vendor=config.device.vendor.value, reason=reason)

    record.source = SOURCE_REJECTED
    record.reason = reason
    entry["review_state"][item_id] = {"status": "rejected", "mapping_id": None}

    return ReviewActionResponse(
        item=_build_item(entry, config_index, config.ai_mappings[record_index]),
        scan=build_scan_response(scan_id),
    )


# ── Endpoints: provisional results → recognizers (Phase 6) ───────────────────

def _unknown_config(entry: dict, config_index: int) -> NormalizedConfig:
    try:
        config: NormalizedConfig = entry["configs"][config_index]
    except IndexError:
        raise HTTPException(404, "Config not found in this scan")
    if config.device.vendor != Vendor.UNKNOWN:
        raise HTTPException(422, f"The {config.device.vendor.value} parser reads this config; recognizers "
                                 "are for configurations no confirmed parser reads")
    return config


def _ai_candidates(config: NormalizedConfig, control_id: str) -> list[_Candidate]:
    """Verified AI judge proposals for this control: lines an administrator can confirm, like heuristics."""
    return [_Candidate(f.predicate, f.value, f.evidence.line_numbers, f.subject, f.scope, f.unit)
            for f in config.ai_facts if f.value is not None and f.control_id == control_id]


def _control(control_id: str):
    control = CONTROLS.get(control_id)
    if control is None:
        raise HTTPException(404, f"Unknown control '{control_id}'")
    return control


def _status_label(result: Optional[ControlResult]) -> str:
    if result is None:
        return "—"
    return result.status.value + (f" ({result.assurance.value})" if result.assurance else "")


def _replay(recognizer: LearnedMapping) -> tuple[int, list[ReplayChangeSchema]]:
    """Evaluate every stored unknown-vendor config with and without the recognizer."""
    # ponytail: scans live in memory, so "past configs" are this process's scans; persist scans to replay history
    configs = list({id(c): c for e in get_scan_store().values() for c in e["configs"]
                    if c.device.vendor == Vendor.UNKNOWN}.values())
    changes = []
    for config in configs:
        before = {(r.control_id, r.scope): r for r in evaluate_controls(config)}
        for result in evaluate_controls(config, extra_recognizers=[recognizer]):
            old = before.get((result.control_id, result.scope))
            if _status_label(old) != _status_label(result):
                changes.append(ReplayChangeSchema(hostname=config.device.hostname, control_id=result.control_id,
                                                  before=_status_label(old), after=_status_label(result)))
    return len(configs), changes


def _draft(scan_id: str, body: RecognizerDraftRequest) -> tuple[LearnedMapping, list[str]]:
    entry = _get_entry(scan_id)
    config = _unknown_config(entry, body.config_index)
    control = _control(body.control_id)
    try:
        fields = draft_recognizer(config.raw_lines, control.needs, body.line_number,
                                  _ai_candidates(config, control.control_id))
    except LookupError as e:
        raise HTTPException(404, str(e))

    for name, override in (("command_pattern", body.command_pattern), ("scope_template", body.scope_template),
                           ("constant_value", body.value)):
        if override is not None:
            fields[name] = override.strip() or None
    if body.any_dialect:
        fields["dialect_fingerprint"] = None
    mapping = LearnedMapping(concept=control.title, normalized_field="", extraction_method=EXTRACTION_RECOGNIZER,
                             confirmed=True, negatives=list(body.negatives), **fields)
    mapping.command_pattern = mapping.command_pattern or ""
    try:
        return validate_mapping(mapping), []
    except MappingValidationError as e:
        return mapping, [str(e)]


def _draft_schema(m: LearnedMapping) -> RecognizerDraftSchema:
    return RecognizerDraftSchema(
        concept=m.concept, predicate=m.predicate, subject=m.subject, command_pattern=m.command_pattern,
        scope_template=m.scope_template, value=m.constant_value, dialect_fingerprint=m.dialect_fingerprint,
        example_line=m.example_line, negatives=m.negatives,
    )


@router.get("/scans/{scan_id}/provisional", response_model=ProvisionalQueueResponse)
async def list_provisional_results(scan_id: str):
    """Undecided or provisional control results and the heuristic lines an admin can confirm."""
    entry = _get_entry(scan_id)
    items = []
    for index, config in enumerate(entry["configs"]):
        if config.device.vendor != Vendor.UNKNOWN:
            continue
        seen = set()
        for result in _device_results(entry.get("result"), entry["configs"], index):
            if (result.control_id in seen or result.assurance in DECISIVE_ASSURANCE
                    or result.status not in (Status.PASS, Status.FAIL, Status.UNKNOWN)):
                continue
            lines = provisional_lines(config.raw_lines, CONTROLS[result.control_id].needs,
                                      _ai_candidates(config, result.control_id))
            if not lines:
                continue
            seen.add(result.control_id)
            items.append(ProvisionalItemSchema(
                config_index=index, control_id=result.control_id, question=CONTROLS[result.control_id].question,
                status=result.status.value, assurance=result.assurance.value if result.assurance else None,
                reason=result.reason,
                lines=[ProvisionalLineSchema(line_number=n, text=config.raw_lines[n - 1].strip(),
                                             predicate=c.predicate, subject=c.subject, value=c.value)
                       for n, c in lines],
            ))
    return ProvisionalQueueResponse(scan_id=scan_id, items=items)


@router.post("/scans/{scan_id}/recognizers/draft", response_model=RecognizerDraftResponse)
async def draft_recognizer_from_line(scan_id: str, body: RecognizerDraftRequest):
    """Draft a recognizer from a provisional line (with admin edits), check its gates and replay it."""
    mapping, errors = _draft(scan_id, body)
    checked, changes = (0, []) if errors else _replay(mapping)
    return RecognizerDraftResponse(draft=_draft_schema(mapping), errors=errors, configs_checked=checked,
                                   replay=changes)


@router.post("/scans/{scan_id}/recognizers", response_model=RecognizerSaveResponse)
async def save_recognizer(scan_id: str, body: RecognizerDraftRequest):
    """Confirm: save the recognizer and re-evaluate the scan — its lines are now decided, no AI."""
    mapping, errors = _draft(scan_id, body)
    if errors:
        raise HTTPException(422, errors[0])
    _, changes = _replay(mapping)
    try:
        saved = _repository().save_mapping(mapping, actor=ADMIN_ACTOR)
    except MappingConflictError as e:
        raise HTTPException(409, str(e))
    except MappingValidationError as e:
        raise HTTPException(422, str(e))
    reanalyze_scan(scan_id)
    return RecognizerSaveResponse(mapping=_mapping_schema(saved), replay=changes, scan=build_scan_response(scan_id))


@router.post("/scans/{scan_id}/provisional/reject", response_model=ScanResultResponse)
async def reject_provisional_line(scan_id: str, body: RejectProvisionalRequest):
    """The heuristic misread this line: remember it as reviewed-but-unmapped (no heuristic, no AI)."""
    entry = _get_entry(scan_id)
    config = _unknown_config(entry, body.config_index)
    if body.line_number not in dict(provisional_lines(config.raw_lines, _control(body.control_id).needs,
                                                      _ai_candidates(config, body.control_id))):
        raise HTTPException(404, f"Line {body.line_number} holds no provisional statement for this control")
    _repository().record_rejection(config.raw_lines[body.line_number - 1], vendor=config.device.vendor.value,
                                   reason=body.reason or "Heuristic rejected by administrator")
    reanalyze_scan(scan_id)
    return build_scan_response(scan_id)


# ── Endpoints: learned mappings ───────────────────────────────────────────────

@router.get("/mappings", response_model=list[LearnedMappingSchema])
async def list_learned_mappings(include_inactive: bool = False):
    return [_mapping_schema(m) for m in _repository().list_mappings(include_inactive=include_inactive)]


@router.patch("/mappings/{mapping_id}", response_model=LearnedMappingSchema)
async def update_learned_mapping(mapping_id: int, body: MappingUpdateRequest):
    """Explicit administrator edit of a learned mapping."""
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(422, "No changes supplied")
    try:
        return _mapping_schema(_repository().update_mapping(mapping_id, changes, actor=ADMIN_ACTOR))
    except MappingNotFoundError as e:
        raise HTTPException(404, str(e))
    except MappingConflictError as e:
        raise HTTPException(409, str(e))
    except (MappingValidationError, MappingPermissionError) as e:
        raise HTTPException(422, str(e))


@router.delete("/mappings/{mapping_id}", response_model=LearnedMappingSchema)
async def disable_learned_mapping(mapping_id: int):
    """Deactivate a learned mapping (kept for audit, no longer matched)."""
    try:
        return _mapping_schema(_repository().disable_mapping(mapping_id, actor=ADMIN_ACTOR))
    except MappingNotFoundError as e:
        raise HTTPException(404, str(e))
