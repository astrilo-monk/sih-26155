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
import logging
import re
import uuid
from datetime import datetime
from functools import partial
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from app.parsers.detector import STATUS_UNVERIFIED, VendorIdentification, identify_vendor
from app.analysis.attack_paths import attack_paths
from app.analysis.risk import CRITICALITY, device_risk
from app.analysis.engine import analyze, analyze_multiple, evaluate_controls
from app.analysis.scoring import calculate_posture, control_outcomes
from app.facts.from_normalized import facts_from_config
from app.facts.predicates import NOT_SET, PREDICATES, SNMP_COMMUNITY
from app.controls.catalog import CIS, CONTROLS, ISO, NIST, STIG
from app.controls.frameworks import framework_views
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
    FrameworkViewSchema,
)
from app import config as app_config
from app.config import settings
from app.adaptive import capture_unrecognized_lines
from app.adaptive.context import structural_paths
from app.ai.redaction import Redactor, placeholder
from app import ledger
from app.db.scans import load_scan, save_scan
from app.facts.heuristics import generic_hostname, stated_identity
from app.structure.structured import flatten_json
from app.adaptive.interpreter import interpret_lines
from app.adaptive.mapper import REVIEWABLE_SOURCES, determine_tier
from app.adaptive.relevance import is_security_relevant
from app.adaptive.vendor import EVIDENCE_CONFLICTING, EVIDENCE_IDENTIFIED, assess_vendor_evidence
from app.adaptive.service import AdaptiveService
from app.ai.client import is_available
from app.ai.judge import Budget, judge_config


router = APIRouter()
logger = logging.getLogger(__name__)

# Scans being worked on stay in memory (teaching and remediation need the configuration); a redacted copy of
# each is archived in the database (app.db.scans), so history survives a restart.
# ponytail: the archive is never pruned; add a retention limit if it grows past what the database should hold.
_scan_store: dict[str, dict] = {}
# Frameworks a scan can be limited to at upload; none chosen means all of them
FRAMEWORKS = (NIST, CIS, STIG, ISO)

def config_redactor(configs) -> Redactor:
    """A redactor that knows every secret value in the scanned configs.

    Each config line is redacted with its block path (to collect values) and
    parsed SNMP community names are added, so any of them can be scrubbed from
    text leaving the process: AI prompts and every API response that quotes
    configuration (evidence, reasons, diffs, review lines).
    """
    redactor = Redactor()
    for cfg in configs or []:
        for raw, path in zip(cfg.raw_lines, structural_paths(cfg.raw_lines)):
            redactor.line(raw, path)
        for community in cfg.snmp.communities:
            redactor.add_secret(community.name)
    return redactor


def display_scrub(redactor: Redactor, text):
    """Replace every known secret value that stands as a whole token, for text shown in the browser.

    Stricter about token edges than ``Redactor.scrub`` (which AI prompts keep using): a password
    'console' is removed from ``password console`` but leaves ``remote-console`` readable.
    """
    if not text:
        return text
    for secret in sorted(redactor.secrets, key=len, reverse=True):
        if len(secret) >= 2:
            text = re.sub(rf"(?<![\w$./-]){re.escape(secret)}(?![\w$./-])", placeholder("redacted"), text)
    return text


def redact_lines(redactor: Redactor, lines, scope=()) -> list[str]:
    return [display_scrub(redactor, redactor.line(text, scope)) for text in lines]


def redact_config_text(redactor: Redactor, text: Optional[str]) -> Optional[str]:
    """A whole configuration (or diff) with every secret replaced; block paths keep scope-dependent rules."""
    if text is None:
        return None
    lines = text.split("\n")
    return "\n".join(display_scrub(redactor, redactor.line(line, path))
                     for line, path in zip(lines, structural_paths(lines)))


def _finding_to_schema(f, redactor: Redactor, framework: Optional[str] = None) -> FindingSchema:
    scrub = partial(display_scrub, redactor)
    return FindingSchema(
        rule_id=f.rule_id,
        title=scrub(f.title),
        severity=f.severity.value,
        description=scrub(f.description),
        device_hostname=f.device_hostname,
        vendor=f.vendor,
        config_index=f.config_index,
        evidence_lines=redact_lines(redactor, f.evidence_lines),
        line_numbers=f.line_numbers,
        security_impact=scrub(f.security_impact),
        recommendation=scrub(f.recommendation),
        compliance=[
            ComplianceMappingSchema(
                framework=c.framework,
                control_id=c.control_id,
                description=c.description,
                version=c.version,
            ) for c in f.compliance if framework in (None, c.framework)
        ],
        ai_explanation=scrub(f.ai_explanation),
        category=f.category,
        assurance=f.assurance,
    )


def fact_value(redactor: Redactor, fact):
    """A fact's value as it may be shown: secrets scrubbed, absence as "not_set"."""
    if fact.predicate == SNMP_COMMUNITY and fact.value is not NOT_SET:
        # SNMP community strings are credentials: which one is configured is never shown, only that one is
        return placeholder("redacted")

    def shown(value):
        if value is NOT_SET:
            return "not_set"
        if isinstance(value, (list, tuple)):
            return [shown(v) for v in value]
        if isinstance(value, str):
            return display_scrub(redactor, value)
        return value
    return shown(fact.value)


def _result_to_schema(result: ControlResult, config_index: int, redactor: Redactor,
                      vendor: Optional[Vendor] = None) -> ControlResultSchema:
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
        reason=display_scrub(redactor, result.reason),
        evidence=EvidenceSchema(
            line_numbers=list(result.evidence.line_numbers),
            lines=redact_lines(redactor, result.evidence.text, result.evidence.scope_path),
            scope_path=list(result.evidence.scope_path),
        ),
        # the evidence chain: the normalized facts this answer read, and the requirements it answers
        facts=[{"field": f.predicate, "subject": f.subject, "value": fact_value(redactor, f), "unit": f.unit,
                "assurance": f.assurance.value, "line_numbers": list(f.evidence.line_numbers)}
               for f in (result.facts or [])],
        requirements=[{"framework": m.framework, "version": m.version, "requirement_id": m.requirement_id,
                       "title": m.title} for m in control.mappings if m.vendor is None or m.vendor == vendor],
    )


def _device_posture(results: list[ControlResult]) -> dict:
    posture = calculate_posture([results])
    return {"posture": posture.posture, "coverage": posture.coverage}


def _device_results(result, configs: list[NormalizedConfig], config_index: int) -> list[ControlResult]:
    """Control results for one config. Controls are deterministic, so a scan
    without a stored compliance result (display-only) is still evaluated."""
    if result is None:
        return evaluate_controls(configs[config_index])
    if config_index >= len(result.device_results):
        return []
    return result.device_results[config_index]


def mapping_record_to_schema(m: AIFieldMapping, redactor: Optional[Redactor] = None) -> AIFieldMappingSchema:
    redactor = redactor or Redactor()
    scrub = partial(display_scrub, redactor)
    return AIFieldMappingSchema(
        line_number=m.line_number,
        raw_line=scrub(redactor.line(m.raw_line)),
        normalized_field=m.normalized_field,
        extracted_value=scrub(m.extracted_value),
        confidence=m.confidence,
        confidence_tier=m.confidence_tier,
        reasoning=scrub(m.reasoning),
        source=m.source,
        status=m.status,
        likely_vendor=m.likely_vendor,
        security_concept=m.security_concept,
        final_value=scrub(m.final_value),
        mapping_id=m.mapping_id,
        reason=scrub(m.reason),
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
    redactor: Optional[Redactor] = None,
) -> AdaptiveScanInfoSchema:
    """Build the adaptive response info for one config."""
    results = results or []
    redactor = redactor or config_redactor([config])
    scrub = partial(display_scrub, redactor)
    records_by_line = {m.line_number: m for m in config.ai_mappings}

    lines_schema = [
        AdaptiveLineSchema(
            line_number=ln.line_number,
            raw_line=scrub(redactor.line(ln.raw_line, ln.structural_path)),
            vendor=ln.vendor,
            context_before=redact_lines(redactor, ln.context_before),
            context_after=redact_lines(redactor, ln.context_after),
            structural_path=redact_lines(redactor, ln.structural_path),
        )
        for ln in config.unrecognized_lines
    ]

    interp_schema = [
        AdaptiveInterpretationSchema(
            line_number=r.line_number,
            raw_line=scrub(redactor.line(r.raw_line)),
            likely_vendor=r.likely_vendor,
            security_concept=r.security_concept,
            normalized_field=r.normalized_field,
            extracted_value=scrub(r.extracted_value),
            value_evidence=scrub(redactor.line(r.value_evidence)) if r.value_evidence else r.value_evidence,
            confidence=r.confidence.value,
            numeric_confidence=r.numeric_confidence,
            confidence_tier=(
                records_by_line[r.line_number].confidence_tier
                if r.line_number in records_by_line
                else determine_tier(r.effective_confidence).value
            ),
            reasoning=scrub(r.reasoning),
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
                f"{identification.reason} -vendor unverified, so no vendor parser or defaults were used; "
                "controls rely on mappings and provisional heuristics"
            )
        else:
            reason = ("Vendor could not be identified -no vendor parser or defaults were used; "
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
                f"({', '.join(undecided)}) -reported as not configured / unknown, "
                "never failed from missing data"
            )
        if not assessed:
            reasons.append(
                "No control could be decided from confirmed evidence (provisional verdicts are not scored) -"
                "it is reported as not assessed rather than scored"
            )
    if ai_unavailable:
        reasons.append(
            f"AI interpretation was unavailable for {ai_unavailable} line(s) -"
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
        ai_mappings=[mapping_record_to_schema(m, redactor) for m in config.ai_mappings],
        config_index=config_index,
        hostname=config.device.hostname,
        vendor=_vendor_str(config),
        ai_called=run.get("ai_called", False),
        ai_calls=run.get("ai_calls", 0),
        ai_cache_hits=run.get("ai_cache_hits", 0),
        learned_matches=sum(1 for m in config.ai_mappings if m.source == "learned_mapping"),
        pending_review=pending,
        score_provisional=bool(reasons),
        provisional_reasons=[scrub(r) for r in reasons],
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
    # a JSON export (cloud security group, NSG, config_db) becomes one statement per object
    if (flat := flatten_json(raw_config)) is not None:
        raw_config = "\n".join(flat)
    raw_lines = raw_config.splitlines()

    normalized = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname=generic_hostname(raw_lines) or "unknown"),
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
    archive_scan(scan_id)


def archive_scan(scan_id: str) -> None:
    """Persist what the browser sees of this scan (redacted), so history survives a restart (app.db.scans)."""
    from app.api.routes.remediation import _device_plan  # remediation imports this module

    plans = []
    for index in range(len(_scan_store[scan_id]["configs"])):
        try:
            plans.append(_device_plan(_scan_store[scan_id], index, {}).model_dump(mode="json"))
        except Exception:  # a scan is worth keeping even when remediation cannot be planned
            plans.append(None)
    response = build_scan_response(scan_id).model_dump(mode="json")
    save_scan(scan_id, _scan_store[scan_id]["timestamp"], response, plans)
    ledger.append("scan", scan_id, response)


def archived_scan(scan_id: str) -> Optional[ScanResultResponse]:
    """A scan this process no longer holds, restored read-only from the archive, or None."""
    stored = load_scan(scan_id)
    return ScanResultResponse(**{**stored[0], "archived": True}) if stored else None


def is_configuration(config: NormalizedConfig) -> bool:
    """Whether the uploaded file holds device configuration at all.

    A confirmed vendor answers it by itself. Otherwise: no line of the file says anything about any
    security setting -prose, a README, an empty template. Such a file is reported as unreadable and
    never scored; an unfamiliar *configuration* is a different thing and is analysed generically.
    """
    return (config.device.vendor != Vendor.UNKNOWN
            or any(is_security_relevant(line) for line in config.raw_lines))


def build_scan_response(scan_id: str) -> ScanResultResponse:
    entry = _scan_store[scan_id]
    configs = entry["configs"]
    result = entry.get("result")
    # Every configuration quote in the response is redacted with its own config's secrets:
    # the browser never receives a secret, and one config's weak password never blanks words in another
    redactors = [config_redactor([cfg]) for cfg in configs]
    identifications = entry.get("identifications") or [None] * len(configs)
    device_results = [_device_results(result, configs, idx) for idx in range(len(configs))]
    infos = [
        _build_adaptive_info(
            cfg, run, idx, identifications[idx],
            assessed=bool(result is not None and result.devices[idx].get("assessed", True)),
            results=device_results[idx],
            redactor=redactors[idx],
        )
        for idx, (cfg, run) in enumerate(zip(configs, entry["adaptive_runs"]))
        if run is not None
    ]
    results_schema = [
        _result_to_schema(r, idx, redactors[idx], configs[idx].device.vendor)
        for idx, results in enumerate(device_results) for r in results
    ]
    selected = entry.get("framework")
    views = [v for v in framework_views(device_results) if selected in (None, v["framework"])]
    for view in views:
        for requirement in view["requirements"]:
            for control in requirement["controls"]:
                own = redactors[control["config_index"]]
                control["reason"] = display_scrub(own, control["reason"])
                control["evidence"]["lines"] = redact_lines(own, control["evidence"]["lines"])
    adaptive = infos[0] if infos else None
    identification_schemas = [
        _identification_schema(ident, idx) for idx, ident in enumerate(identifications) if ident is not None
    ]

    posture = calculate_posture(device_results)
    outcomes = control_outcomes(device_results)
    posture_fields = dict(
        posture=posture.posture,
        coverage=posture.coverage,
        posture_bounds=list(posture.bounds) if posture.bounds else None,
        critical_unassessed=posture.critical_unassessed,
        frameworks=[FrameworkViewSchema(**view) for view in views],
        framework=selected,
        unreadable_configs=[idx for idx, cfg in enumerate(configs) if not is_configuration(cfg)],
        assessed_count=sum(1 for o in outcomes.values() if o in ("pass", "fail")),
        unresolved_count=sum(1 for o in outcomes.values() if o == "undecided"),
        # built from the redacted results above, so a path quotes nothing the results do not
        attack_paths=[{"config_index": idx, **path} for idx in range(len(configs))
                      for path in attack_paths([r.model_dump() for r in results_schema if r.config_index == idx])],
    )

    if result is None:
        # AI unavailable and nothing could be normalized -display-only
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
        # each device's own posture and coverage, from the same calculation as the scan's (fleet view)
        devices=[{**device, **_device_posture(device_results[idx]),
                  "risk": device_risk([r.model_dump() for r in results_schema if r.config_index == idx],
                                      [p for p in posture_fields["attack_paths"] if p["config_index"] == idx],
                                      **entry.get("context", {}))}
                 for idx, device in enumerate(result.devices)],
        findings=[_finding_to_schema(f, redactors[f.config_index], selected) for f in result.findings],
        adaptive=adaptive,
        adaptive_configs=infos,
        vendor_identification=identification_schemas,
        results=results_schema,
        **posture_fields,
    )


def validated_framework(framework: Optional[str]) -> Optional[str]:
    """The benchmark chosen at upload; controls always run in full, only the reporting is limited."""
    framework = framework or None
    if framework is not None and framework not in FRAMEWORKS:
        raise HTTPException(422, f"Unknown framework '{framework}': choose one of {', '.join(FRAMEWORKS)}")
    return framework


def run_scan(sources: list[tuple[str, str]], framework: Optional[str] = None,
             context: Optional[dict] = None) -> ScanResultResponse:
    """Analyse configurations that are already text, and return the scan they produce.

    ``sources`` are ``(name, configuration)`` pairs. The name is only for error messages: nothing in
    the pipeline reads it, so a configuration collected from a live device (``routes.collect``) takes
    exactly the same path as an uploaded file, with the same redaction and the same AI rules.
    """
    service = _new_adaptive_service()
    configs: list[NormalizedConfig] = []
    adaptive_runs: list[Optional[dict]] = []
    identifications: list[VendorIdentification] = []
    had_unknown_vendor = False
    had_ai_available = False

    for name, raw_config in sources:
        if not raw_config.strip():
            raise HTTPException(400, f"'{name}' is empty")
        # guarded here rather than per caller: a device can answer with a configuration just as large
        # as a file can be, and a collected one never passed through the upload check
        if len(raw_config.encode("utf-8")) > settings.max_file_size:
            raise HTTPException(413, f"'{name}' exceeds the 2MB limit")

        identification = identify_vendor(raw_config)
        identifications.append(identification)

        if not identification.confirmed:
            # Unknown, or resembling a vendor whose grammar the config does not
            # follow (UNVERIFIED): device.vendor stays UNKNOWN. Only a confirmed
            # deterministic profile selects vendor-specific rules; AI vendor
            # opinions are reported as evidence in the adaptive info instead.
            had_unknown_vendor = True
            normalized = _process_unknown_vendor(raw_config, name)
            # learned mappings and recognizers only: the AI judge below is the only AI for unknown vendors
            outcome = service.process(normalized, use_ai=False, report_unresolved=False)
        else:
            normalized = identification.config
            capture_unrecognized_lines(normalized)
            # LEGACY, off by default: interpretations only reach the review queue (never applied without an admin)
            use_ai = app_config.settings.adaptive_ai_for_known_vendors
            outcome = service.process(normalized, use_ai=use_ai, report_unresolved=use_ai)

        # serial / model / version, where the uploaded text states them and no parser already read them
        for item, value in stated_identity(normalized.raw_lines).items():
            if not getattr(normalized.device, item):
                setattr(normalized.device, item, value)

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

    # settings read at call time: tests (and a config reload) replace the settings object
    if had_unknown_vendor and is_available():
        had_ai_available = True
        budget = Budget(app_config.settings.ai_judge_max_calls_per_scan)
        for cfg, run in zip(configs, adaptive_runs):
            if cfg.device.vendor != Vendor.UNKNOWN:
                continue
            calls, hits = budget.calls, budget.cache_hits
            try:
                judge_config(cfg, evaluate_controls(cfg), budget)
            except Exception as e:  # the AI is an escalation: a judge failure never fails the scan
                logger.warning("AI judge failed: %s", e)
                cfg.ai_facts = []
            run.update(ai_available=True, ai_called=run["ai_called"] or budget.calls > calls,
                       ai_calls=budget.calls - calls, ai_cache_hits=budget.cache_hits - hits)

    scan_id = str(uuid.uuid4())
    anything_applied =any(m.applied for cfg in configs for m in cfg.ai_mappings) or any(
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
        "framework": framework,
        # asset criticality and internet exposure the operator stated at upload (risk only; never a verdict)
        "context": context or {},
    }

    if not (had_unknown_vendor and not had_ai_available and not anything_applied):
        reanalyze_scan(scan_id)
    else:
        archive_scan(scan_id)

    return build_scan_response(scan_id)


@router.post("/scan", response_model=ScanResultResponse)
async def scan_configs(files: list[UploadFile] = File(...), framework: Optional[str] = Form(None),
                       criticality: Optional[str] = Form(None), internet_facing: bool = Form(False)):
    """
    Upload one or more config files for security analysis.
    Returns findings, score, and device info.

    Unknown-vendor configs get recognizer, mapping and heuristic facts; then,
    when AI is available, the AI judge (``app.ai.judge``) -the only AI path for
    them -reads only the scopes of controls still UNKNOWN or NOT_CONFIGURED,
    within a per-scan call budget and a cache, and adds verified provisional
    facts. If AI is unavailable and nothing could be read, the scan degrades
    gracefully to display-only results.

    Known-vendor configs use their parsers; confirmed learned mappings are
    applied to lines those parsers do not understand. The legacy interpreter
    (``adaptive_ai_for_known_vendors``, off by default) only fills the review queue.
    """
    if not files:
        raise HTTPException(400, "No files uploaded")
    framework = validated_framework(framework)
    if criticality not in (None, "", *CRITICALITY):
        raise HTTPException(422, f"criticality must be one of: {', '.join(CRITICALITY)}")

    sources: list[tuple[str, str]] = []
    for file in files:
        content = await file.read()

        if len(content) > settings.max_file_size:
            raise HTTPException(413, f"File '{file.filename}' exceeds 2MB limit")

        try:
            sources.append((file.filename, content.decode("utf-8")))
        except UnicodeDecodeError:
            raise HTTPException(400, f"File '{file.filename}' is not a valid text file")

    return run_scan(sources, framework, {"criticality": criticality or None, "internet_facing": internet_facing})


@router.get("/scan/{scan_id}", response_model=ScanResultResponse)
async def get_scan(scan_id: str):
    """Retrieve a previous scan result."""
    if scan_id not in _scan_store:
        if archived := archived_scan(scan_id):
            return archived
        raise HTTPException(404, "Scan not found")
    return build_scan_response(scan_id)


@router.get("/catalog")
async def control_catalog():
    """Every check: its question, what it reads, and every framework requirement it answers (with versions)."""
    controls = [{
        "control_id": c.control_id, "title": c.title, "question": c.question, "category": c.category,
        "severity": c.severity.value, "kind": c.kind.value, "reads": list(c.needs),
        "requirements": [{"framework": m.framework, "version": m.version, "requirement_id": m.requirement_id,
                          "title": m.title, "vendor": m.vendor.value if m.vendor else None} for m in c.mappings],
    } for c in CONTROLS.values()]
    by_framework: dict[str, set] = {}
    for c in controls:
        for r in c["requirements"]:
            by_framework.setdefault(r["framework"], set()).add((r["version"], r["requirement_id"]))
    return {"controls": controls, "requirements": {f: len(ids) for f, ids in sorted(by_framework.items())},
            "requirement_total": sum(len(ids) for ids in by_framework.values())}


@router.get("/scan/{scan_id}/baseline")
async def security_baseline(scan_id: str, config_index: int = 0):
    """The vendor-neutral Security Baseline Model of one configuration: every normalized field, what the
    configuration says about it and the line that says so. Every control reads these fields, never vendor syntax.

    Redacted like every response that quotes configuration: secret values never appear, in a value or a line.
    """
    entry = live_scan(scan_id)
    if not 0 <= config_index < len(entry["configs"]):
        raise HTTPException(404, f"This scan has no configuration {config_index}")
    config: NormalizedConfig = entry["configs"][config_index]
    redactor = config_redactor([config])
    facts = facts_from_config(config)
    settings = [{
        "field": f.predicate,
        "subject": f.subject,
        "scope": display_scrub(redactor, f.scope),
        "value": fact_value(redactor, f),
        "unit": f.unit,
        "assurance": f.assurance.value,
        "lines": [{"number": n, "text": t} for n, t in
                  zip(f.evidence.line_numbers, redact_lines(redactor, f.evidence.text))],
        "note": display_scrub(redactor, f.provenance) or None,
    } for f in facts if f.predicate in PREDICATES]
    stated = {s["field"] for s in settings}
    device = config.device
    return {
        "schema": "netauditai.security-baseline/1",
        "device": {"hostname": display_scrub(redactor, device.hostname), "vendor": device.vendor.value,
                   "os_version": device.os_version, "model": device.model, "serial": device.serial},
        "settings": settings,
        "not_stated": sorted(PREDICATES - stated),
        "read_by": {p: sorted(c.control_id for c in CONTROLS.values() if p in c.needs) for p in sorted(PREDICATES)},
    }


@router.get("/scan/{scan_id}/status")
async def scan_status(scan_id: str):
    """Whether this backend can open the scan: in memory (``archived`` false), or restored read-only from the
    scan archive after a restart (``archived`` true).

    Always 200: history checks every stored entry, and an expired scan is an answer, not an error.
    """
    if scan_id in _scan_store:
        return {"scan_id": scan_id, "held": True, "archived": False}
    archived = load_scan(scan_id) is not None
    return {"scan_id": scan_id, "held": archived, "archived": archived}


def get_scan_store() -> dict:
    """Expose store for other routes that need scan data."""
    return _scan_store


def live_scan(scan_id: str) -> dict:
    """The in-memory scan an action needs; an archived scan is explained, not reported missing."""
    entry = _scan_store.get(scan_id)
    if entry:
        return entry
    if load_scan(scan_id) is not None:
        raise HTTPException(409, "This scan was restored from history: its configuration is not kept, because it "
                                 "holds secrets. Upload the configuration again to teach or fix it.")
    raise HTTPException(404, "Scan not found")


def get_scan_result_or_409(stored: dict):
    """Return the compliance result of a stored scan, or explain why there is none."""
    result = stored.get("result")
    if result is None:
        raise HTTPException(
            409,
            "This scan has no compliance result yet -AI interpretation was unavailable. "
            "Review the adaptive lines on the Review & Recognizers page first.",
        )
    return result
