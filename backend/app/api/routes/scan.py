"""
Scan API routes.

Handles file upload, vendor detection, parsing, adaptive enrichment and
analysis. This is the main entry point for the security audit workflow.

    Config → Vendor identification (fingerprint → parser → parse coverage)
           → confirmed vendor: parser output   OR   unknown / unverified: adaptive path
           → NormalizedConfig → AdaptiveService (learned mappings → AI fallback
             → confidence/validation → safe normalization)
           → existing deterministic compliance engine → findings / score
"""

from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, UploadFile, File, HTTPException
from app.parsers.detector import STATUS_UNVERIFIED, VendorIdentification, identify_vendor
from app.analysis.engine import analyze, analyze_multiple, evaluate_controls
from app.analysis.scoring import calculate_posture
from app.facts.from_normalized import facts_from_config
from app.controls.catalog import CONTROLS
from app.models.results import ControlResult, Status
from app.models.normalized import Vendor, NormalizedConfig, DeviceInfo, AIFieldMapping
from app.api.schemas import (
    ScanResultResponse,
    FindingSchema,
    ComplianceMappingSchema,
    AdaptiveLineSchema,
    AdaptiveInterpretationSchema,
    AdaptiveScanInfoSchema,
    AIFieldMappingSchema,
    VendorEvidenceSchema,
    VendorIdentificationSchema,
    ControlResultSchema,
    EvidenceSchema,
)
from app.config import settings
from app.adaptive import capture_unrecognized_lines
from app.adaptive.interpreter import interpret_lines
from app.adaptive.mapper import REVIEWABLE_SOURCES, determine_tier
from app.adaptive.vendor import EVIDENCE_CONFLICTING, EVIDENCE_IDENTIFIED, assess_vendor_evidence
from app.adaptive.service import AdaptiveService
from app.ai.client import is_available


router = APIRouter()

# Keep scan results in memory for the demo.
# A real product would use a database.
_scan_store: dict[str, dict] = {}

def _finding_to_schema(f) -> FindingSchema:
    return FindingSchema(
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
                version=c.version,
            ) for c in f.compliance
        ],
        ai_explanation=f.ai_explanation,
        category=f.category,
        assurance=f.assurance,
    )


def _result_to_schema(result: ControlResult, config_index: int) -> ControlResultSchema:
    control = CONTROLS[result.control_id]
    return ControlResultSchema(
        config_index=config_index,
        control_id=result.control_id,
        title=control.title,
        question=control.question,
        kind=control.kind.value,
        category=control.category,
        severity=(result.failure.severity if result.failure else control.severity).value,
        status=result.status.value,
        assurance=result.assurance.value if result.assurance else None,
        proposed_status=result.proposed_status.value if result.proposed_status else None,
        device_hostname=result.device_hostname,
        vendor=result.vendor,
        scope=result.scope,
        reason=result.reason,
        evidence=EvidenceSchema(
            line_numbers=list(result.evidence.line_numbers),
            lines=list(result.evidence.text),
            scope_path=list(result.evidence.scope_path),
        ),
    )


def _device_results(result, configs: list[NormalizedConfig], config_index: int) -> list[ControlResult]:
    """Control results for one config. Controls are deterministic, so a scan
    without a stored compliance result (display-only) is still evaluated."""
    if result is None:
        return evaluate_controls(configs[config_index])
    if config_index >= len(result.device_results):
        return []
    return result.device_results[config_index]


def mapping_record_to_schema(m: AIFieldMapping) -> AIFieldMappingSchema:
    return AIFieldMappingSchema(
        line_number=m.line_number,
        raw_line=m.raw_line,
        normalized_field=m.normalized_field,
        extracted_value=m.extracted_value,
        confidence=m.confidence,
        confidence_tier=m.confidence_tier,
        reasoning=m.reasoning,
        source=m.source,
        status=m.status,
        likely_vendor=m.likely_vendor,
        security_concept=m.security_concept,
        final_value=m.final_value,
        mapping_id=m.mapping_id,
        reason=m.reason,
    )


def _vendor_str(config: NormalizedConfig) -> str:
    vendor = config.device.vendor
    return vendor.value if hasattr(vendor, "value") else str(vendor)


def _identification_schema(identification: VendorIdentification, config_index: int) -> VendorIdentificationSchema:
    coverage = identification.coverage
    return VendorIdentificationSchema(
        config_index=config_index,
        detected_vendor=identification.detected_vendor.value,
        status=identification.status,
        parse_coverage=round(coverage.ratio, 3) if coverage else None,
        uncovered_lines=coverage.uncovered_count if coverage else 0,
        reason=identification.reason,
    )


def _build_adaptive_info(
    config: NormalizedConfig,
    run: dict,
    config_index: int,
    identification: Optional[VendorIdentification] = None,
    assessed: bool = False,
    results: Optional[list[ControlResult]] = None,
) -> AdaptiveScanInfoSchema:
    """Build the adaptive response info for one config."""
    results = results or []
    records_by_line = {m.line_number: m for m in config.ai_mappings}

    lines_schema = [
        AdaptiveLineSchema(
            line_number=ln.line_number,
            raw_line=ln.raw_line,
            vendor=ln.vendor,
            context_before=list(ln.context_before),
            context_after=list(ln.context_after),
            structural_path=list(ln.structural_path),
        )
        for ln in config.unrecognized_lines
    ]

    interp_schema = [
        AdaptiveInterpretationSchema(
            line_number=r.line_number,
            raw_line=r.raw_line,
            likely_vendor=r.likely_vendor,
            security_concept=r.security_concept,
            normalized_field=r.normalized_field,
            extracted_value=r.extracted_value,
            value_evidence=r.value_evidence,
            confidence=r.confidence.value,
            numeric_confidence=r.numeric_confidence,
            confidence_tier=(
                records_by_line[r.line_number].confidence_tier
                if r.line_number in records_by_line
                else determine_tier(r.effective_confidence).value
            ),
            reasoning=r.reasoning,
            status=r.status.value,
            source=records_by_line[r.line_number].source if r.line_number in records_by_line else None,
        )
        for r in run.get("interpretations", [])
    ]

    pending = sum(1 for m in config.ai_mappings if m.source in REVIEWABLE_SOURCES)
    ai_unavailable = sum(
        1 for m in config.ai_mappings
        if m.source in REVIEWABLE_SOURCES and m.status == "ai_unavailable"
    )
    evidence = assess_vendor_evidence(config.ai_mappings)

    reasons = []
    if config.device.vendor == Vendor.UNKNOWN:
        if identification is not None and identification.status == STATUS_UNVERIFIED:
            reason = (
                f"Configuration resembles '{identification.detected_vendor.value}', but "
                f"{identification.reason} — vendor unverified, so no vendor parser or defaults were used; "
                "controls rely on mappings and provisional heuristics"
            )
        else:
            reason = ("Vendor could not be identified — no vendor parser or defaults were used; "
                      "controls rely on mappings and provisional heuristics")
        if evidence.status == EVIDENCE_IDENTIFIED:
            reason += (
                f" (configuration syntax suggests '{evidence.likely_vendor}'; "
                "reported as evidence only)"
            )
        elif evidence.status == EVIDENCE_CONFLICTING:
            reason += " (adaptive vendor evidence is conflicting)"
        reasons.append(reason)
        undecided = sorted({
            r.control_id for r in results if r.status in (Status.NOT_CONFIGURED, Status.UNKNOWN)
        })
        if undecided:
            reasons.append(
                f"Evidence was not found or not decidable for {len(undecided)} control(s) "
                f"({', '.join(undecided)}) — reported as not configured / unknown, "
                "never failed from missing data"
            )
        if not assessed:
            reasons.append(
                "No control could be decided from confirmed evidence (provisional verdicts are not scored) — "
                "it is reported as not assessed rather than scored"
            )
    if ai_unavailable:
        reasons.append(
            f"AI interpretation was unavailable for {ai_unavailable} line(s) — "
            "they were not assessed; map them manually or rescan later"
        )
    if pending:
        reasons.append(
            f"{pending} security-relevant line(s) are awaiting review and were not applied"
        )

    return AdaptiveScanInfoSchema(
        ai_available=run.get("ai_available", False),
        unrecognized_lines=lines_schema,
        interpretations=interp_schema,
        ai_mappings=[mapping_record_to_schema(m) for m in config.ai_mappings],
        config_index=config_index,
        hostname=config.device.hostname,
        vendor=_vendor_str(config),
        ai_called=run.get("ai_called", False),
        learned_matches=sum(1 for m in config.ai_mappings if m.source == "learned_mapping"),
        pending_review=pending,
        score_provisional=bool(reasons),
        provisional_reasons=reasons,
        vendor_evidence=VendorEvidenceSchema(
            likely_vendor=evidence.likely_vendor,
            status=evidence.status,
            supporting_lines=evidence.supporting_lines,
            votes=evidence.votes,
        ),
        ai_unavailable_lines=ai_unavailable,
        assessed=assessed,
    )


def _process_unknown_vendor(raw_config: str, filename: str) -> NormalizedConfig:
    """
    Prepare an unknown-vendor configuration for the adaptive pipeline.

    Creates a minimal NormalizedConfig preserving the raw config and runs
    Phase 1 candidate capture. Enrichment happens in ``AdaptiveService``.
    """
    raw_lines = raw_config.splitlines()

    normalized = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname="unknown"),
        raw_config=raw_config,
        raw_lines=raw_lines,
    )

    # Phase 1: capture security-relevant unrecognized lines
    capture_unrecognized_lines(normalized)

    return normalized


def _new_adaptive_service() -> AdaptiveService:
    # Resolve interpret_lines / is_available at call time so they can be patched.
    return AdaptiveService(interpreter=interpret_lines, ai_available=is_available)


def reanalyze_scan(scan_id: str) -> None:
    """Re-run the deterministic engine on a stored scan's (enriched) configs."""
    entry = _scan_store[scan_id]
    configs = entry["configs"]
    result = analyze(configs[0]) if len(configs) == 1 else analyze_multiple(configs)
    result.scan_id = scan_id
    entry["result"] = result
    entry["is_adaptive_only"] = False
    entry["timestamp"] = result.timestamp


def build_scan_response(scan_id: str) -> ScanResultResponse:
    entry = _scan_store[scan_id]
    configs = entry["configs"]
    result = entry.get("result")
    identifications = entry.get("identifications") or [None] * len(configs)
    device_results = [_device_results(result, configs, idx) for idx in range(len(configs))]
    infos = [
        _build_adaptive_info(
            cfg, run, idx, identifications[idx],
            assessed=bool(result is not None and result.devices[idx].get("assessed", True)),
            results=device_results[idx],
        )
        for idx, (cfg, run) in enumerate(zip(configs, entry["adaptive_runs"]))
        if run is not None
    ]
    results_schema = [
        _result_to_schema(r, idx) for idx, results in enumerate(device_results) for r in results
    ]
    adaptive = infos[0] if infos else None
    identification_schemas = [
        _identification_schema(ident, idx) for idx, ident in enumerate(identifications) if ident is not None
    ]

    posture = calculate_posture(device_results)
    posture_fields = dict(
        posture=posture.posture,
        coverage=posture.coverage,
        posture_bounds=list(posture.bounds) if posture.bounds else None,
        critical_unassessed=posture.critical_unassessed,
    )

    if result is None:
        # AI unavailable and nothing could be normalized — display-only
        return ScanResultResponse(
            scan_id=scan_id,
            timestamp=entry.get("timestamp", datetime.now().isoformat()),
            devices=[{"hostname": cfg.device.hostname, "vendor": _vendor_str(cfg)} for cfg in configs],
            findings=[],
            adaptive=adaptive,
            adaptive_configs=infos,
            vendor_identification=identification_schemas,
            results=results_schema,
            **posture_fields,
        )

    return ScanResultResponse(
        scan_id=scan_id,
        timestamp=result.timestamp,
        score=result.score,
        total_findings=result.total_findings,
        critical=result.critical_count,
        high=result.high_count,
        medium=result.medium_count,
        low=result.low_count,
        devices=result.devices,
        findings=[_finding_to_schema(f) for f in result.findings],
        adaptive=adaptive,
        adaptive_configs=infos,
        vendor_identification=identification_schemas,
        results=results_schema,
        **posture_fields,
    )


@router.post("/scan", response_model=ScanResultResponse)
async def scan_configs(files: list[UploadFile] = File(...)):
    """
    Upload one or more config files for security analysis.
    Returns findings, score, and device info.

    Unknown-vendor configs enter the adaptive pipeline: confirmed learned
    mappings are applied first, then ONE batched AI request interprets the
    remaining security-relevant lines, and the AdaptiveMapper applies only
    validated HIGH-confidence values. The deterministic compliance engine then
    evaluates the enriched config. If AI is unavailable and nothing could be
    normalized, the scan degrades gracefully to display-only results.

    Known-vendor configs use their parsers; confirmed learned mappings are
    applied to lines those parsers do not understand.
    """
    if not files:
        raise HTTPException(400, "No files uploaded")

    service = _new_adaptive_service()
    configs: list[NormalizedConfig] = []
    adaptive_runs: list[Optional[dict]] = []
    identifications: list[VendorIdentification] = []
    had_unknown_vendor = False
    had_ai_available = False

    for file in files:
        content = await file.read()

        if len(content) > settings.max_file_size:
            raise HTTPException(413, f"File '{file.filename}' exceeds 2MB limit")

        try:
            raw_config = content.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(400, f"File '{file.filename}' is not a valid text file")

        if not raw_config.strip():
            raise HTTPException(400, f"File '{file.filename}' is empty")

        identification = identify_vendor(raw_config)
        identifications.append(identification)

        if not identification.confirmed:
            # Unknown, or resembling a vendor whose grammar the config does not
            # follow (UNVERIFIED): device.vendor stays UNKNOWN. Only a confirmed
            # deterministic profile selects vendor-specific rules; AI vendor
            # opinions are reported as evidence in the adaptive info instead.
            had_unknown_vendor = True
            normalized = _process_unknown_vendor(raw_config, file.filename)
            outcome = service.process(normalized, use_ai=True)
            had_ai_available = had_ai_available or outcome.ai_available
        else:
            normalized = identification.config
            capture_unrecognized_lines(normalized)
            use_ai = settings.adaptive_ai_for_known_vendors
            outcome = service.process(normalized, use_ai=use_ai, report_unresolved=use_ai)

        run = None
        if not identification.confirmed or outcome.records:
            run = {
                "interpretations": outcome.interpretations,
                "ai_called": outcome.ai_called,
                "ai_available": outcome.ai_available,
                "candidates": outcome.candidates,
            }
        configs.append(normalized)
        adaptive_runs.append(run)

    scan_id = str(uuid.uuid4())
    anything_applied = any(m.applied for cfg in configs for m in cfg.ai_mappings) or any(
        facts_from_config(cfg) for cfg in configs if cfg.device.vendor == Vendor.UNKNOWN
    )

    _scan_store[scan_id] = {
        "result": None,
        "configs": configs,
        "adaptive_runs": adaptive_runs,
        "identifications": identifications,
        "is_adaptive_only": True,
        "timestamp": datetime.now().isoformat(),
        # item_id -> {"status": accepted|edited|rejected|learned, "mapping_id": int|None}
        "review_state": {},
    }

    if not (had_unknown_vendor and not had_ai_available and not anything_applied):
        reanalyze_scan(scan_id)

    return build_scan_response(scan_id)


@router.get("/scan/{scan_id}", response_model=ScanResultResponse)
async def get_scan(scan_id: str):
    """Retrieve a previous scan result."""
    if scan_id not in _scan_store:
        raise HTTPException(404, "Scan not found")
    return build_scan_response(scan_id)


def get_scan_store() -> dict:
    """Expose store for other routes that need scan data."""
    return _scan_store


def get_scan_result_or_409(stored: dict):
    """Return the compliance result of a stored scan, or explain why there is none."""
    result = stored.get("result")
    if result is None:
        raise HTTPException(
            409,
            "This scan has no compliance result yet — AI interpretation was unavailable. "
            "Review the adaptive lines in the Training tab first.",
        )
    return result
