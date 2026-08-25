"""
Scan API routes.

Handles file upload, vendor detection, parsing, and analysis.
This is the main entry point for the security audit workflow.
"""

from __future__ import annotations
from fastapi import APIRouter, UploadFile, File, HTTPException
from app.parsers.detector import detect_vendor
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.fortinet import FortinetParser
from app.analysis.engine import analyze, analyze_multiple
from app.models.normalized import Vendor, NormalizedConfig
from app.api.schemas import ScanResultResponse, FindingSchema, ComplianceMappingSchema
from app.config import settings

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


@router.post("/scan", response_model=ScanResultResponse)
async def scan_configs(files: list[UploadFile] = File(...)):
    """
    Upload one or more config files for security analysis.
    Returns findings, score, and device info.
    """
    if not files:
        raise HTTPException(400, "No files uploaded")

    configs: list[NormalizedConfig] = []

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
            raise HTTPException(
                422,
                f"Could not identify the vendor for '{file.filename}'. "
                "Supported vendors: Cisco IOS, Fortinet FortiGate."
            )

        parser = PARSERS.get(vendor)
        if not parser:
            raise HTTPException(422, f"No parser available for vendor '{vendor.value}'")

        normalized = parser.parse(raw_config)
        configs.append(normalized)

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

    result = stored["result"]
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
