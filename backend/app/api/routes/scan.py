"""
Scan API routes.

Handles file upload, vendor detection, parsing, and analysis.
This is the main entry point for the security audit workflow.
"""

from __future__ import annotations
import uuid
from fastapi import APIRouter, UploadFile, File, HTTPException
from app.parsers.detector import detect_vendor
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.fortinet import FortinetParser
from app.analysis.engine import analyze, analyze_multiple
from app.models.normalized import Vendor, NormalizedConfig, DeviceInfo
from app.api.schemas import (
    ScanResultResponse,
    FindingSchema,
    ComplianceMappingSchema,
    AdaptiveLineSchema,
    AdaptiveInterpretationSchema,
    AdaptiveScanInfoSchema,
)
from app.config import settings
from app.adaptive import capture_unrecognized_lines
from app.adaptive.interpreter import interpret_lines
from app.ai.interpretation_schemas import InterpretationStatus
from app.ai.client import is_available

router = APIRouter()

# Keep scan results in memory for the demo.
# A real product would use a database.
_scan_store: dict[str, dict] = {}

PARSERS = {
    Vendor.CISCO_IOS: CiscoIOSParser(),
    Vendor.FORTINET: FortinetParser(),
}


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
            ) for c in f.compliance
        ],
        ai_explanation=f.ai_explanation,
        category=f.category,
    )


def _build_adaptive_info(config: NormalizedConfig, interpretations) -> AdaptiveScanInfoSchema:
    """Build the adaptive response info for an unknown-vendor config."""
    lines_schema = [
        AdaptiveLineSchema(
            line_number=ln.line_number,
            raw_line=ln.raw_line,
            vendor=ln.vendor,
            context_before=list(ln.context_before),
            context_after=list(ln.context_after),
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
            confidence=r.confidence.value,
            reasoning=r.reasoning,
            status=r.status.value,
        )
        for r in interpretations
    ]

    return AdaptiveScanInfoSchema(
        ai_available=is_available(),
        unrecognized_lines=lines_schema,
        interpretations=interp_schema,
    )


def _process_unknown_vendor(raw_config: str, filename: str) -> NormalizedConfig:
    """
    Process an unknown-vendor configuration through the adaptive pipeline.

    Creates a minimal NormalizedConfig preserving the raw config, runs
    Phase 1 candidate capture, then Phase 2 Groq interpretation.
    Does NOT call analyze() — AI results are display-only.
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


def _process_known_vendor(raw_config: str, vendor: Vendor) -> NormalizedConfig:
    """Process a known-vendor configuration through the existing parser pipeline."""
    parser = PARSERS.get(vendor)
    if not parser:
        raise HTTPException(422, f"No parser available for vendor '{vendor.value}'")

    normalized = parser.parse(raw_config)
    # Capture unrecognized lines for adaptive parsing
    capture_unrecognized_lines(normalized)
    return normalized


@router.post("/scan", response_model=ScanResultResponse)
async def scan_configs(files: list[UploadFile] = File(...)):
    """
    Upload one or more config files for security analysis.
    Returns findings, score, and device info.

    Unknown-vendor configs enter the adaptive pipeline: Phase 1 captures
    security-relevant unrecognized lines, Phase 2 runs AI interpretation.
    For unknown vendors, results are display-only — the deterministic
    compliance engine is not invoked.
    """
    if not files:
        raise HTTPException(400, "No files uploaded")

    configs: list[NormalizedConfig] = []
    adaptive_infos: list[AdaptiveScanInfoSchema] = []
    had_unknown_vendor = False

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

        vendor = detect_vendor(raw_config)

        if vendor == Vendor.UNKNOWN:
            # Unknown vendor → adaptive pipeline
            normalized = _process_unknown_vendor(raw_config, file.filename)
            had_unknown_vendor = True

            # Phase 2: ONE batched Groq interpretation for this config
            interpretations = interpret_lines(normalized.unrecognized_lines)

            adaptive_infos.append(_build_adaptive_info(normalized, interpretations))
            configs.append(normalized)
        else:
            normalized = _process_known_vendor(raw_config, vendor)
            configs.append(normalized)

    # If ANY config is unknown-vendor, we cannot run the deterministic
    # compliance engine (it would produce misleading empty/incomplete scores).
    # Return adaptive interpretation results as display-only.
    if had_unknown_vendor:
        scan_id = str(uuid.uuid4())
        from datetime import datetime
        timestamp = datetime.now().isoformat()

        _scan_store[scan_id] = {
            "result": None,
            "configs": configs,
            "adaptive_infos": adaptive_infos,
            "is_adaptive_only": True,
        }

        devices = []
        for cfg in configs:
            devices.append({
                "hostname": cfg.device.hostname,
                "vendor": cfg.device.vendor.value if hasattr(cfg.device.vendor, "value") else str(cfg.device.vendor),
            })

        # Build response for the first config (or merge adaptive infos)
        first_config = configs[0]
        first_adaptive = adaptive_infos[0] if adaptive_infos else None

        response_kwargs = dict(
            scan_id=scan_id,
            timestamp=timestamp,
            devices=devices,
            findings=[],
            adaptive=first_adaptive,
        )

        return ScanResultResponse(**response_kwargs)

    # Known vendors — existing deterministic pipeline
    if len(configs) == 1:
        result = analyze(configs[0])
    else:
        result = analyze_multiple(configs)

    # Store for later retrieval (remediation, assistant, etc.)
    _scan_store[result.scan_id] = {
        "result": result,
        "configs": configs,
    }

    return ScanResultResponse(
        scan_id=result.scan_id,
        timestamp=result.timestamp,
        score=result.score,
        total_findings=result.total_findings,
        critical=result.critical_count,
        high=result.high_count,
        medium=result.medium_count,
        low=result.low_count,
        devices=result.devices,
        findings=[_finding_to_schema(f) for f in result.findings],
    )


@router.get("/scan/{scan_id}", response_model=ScanResultResponse)
async def get_scan(scan_id: str):
    """Retrieve a previous scan result."""
    stored = _scan_store.get(scan_id)
    if not stored:
        raise HTTPException(404, "Scan not found")

    result = stored.get("result")

    if result is None and stored.get("is_adaptive_only"):
        # Unknown-vendor adaptive-only scan
        configs = stored.get("configs", [])
        adaptive_infos = stored.get("adaptive_infos", [])
        from datetime import datetime
        # Re-construct using stored data; timestamp was set at scan time
        # We store the timestamp alongside for retrieval
        return ScanResultResponse(
            scan_id=scan_id,
            timestamp=stored.get("timestamp", datetime.now().isoformat()),
            devices=[
                {
                    "hostname": cfg.device.hostname,
                    "vendor": cfg.device.vendor.value if hasattr(cfg.device.vendor, "value") else str(cfg.device.vendor),
                }
                for cfg in configs
            ],
            findings=[],
            adaptive=adaptive_infos[0] if adaptive_infos else None,
        )

    return ScanResultResponse(
        scan_id=result.scan_id,
        timestamp=result.timestamp,
        score=result.score,
        total_findings=result.total_findings,
        critical=result.critical_count,
        high=result.high_count,
        medium=result.medium_count,
        low=result.low_count,
        devices=result.devices,
        findings=[_finding_to_schema(f) for f in result.findings],
    )


def get_scan_store() -> dict:
    """Expose store for other routes that need scan data."""
    return _scan_store
