"""
Control evaluation engine.

Runs every catalog control against a normalized config through the generic
evaluator (``controls/evaluate.py``). Each control yields ControlResults
(PASS / FAIL / NOT_CONFIGURED / UNKNOWN / N_A); Findings are the view of the
FAIL results, and the legacy score is computed from them.
"""

from __future__ import annotations

import uuid

from app.analysis.scoring import calculate_score
from app.controls.evaluate import evaluate_controls
from app.controls.views import finding_from_result
from app.models.findings import ScanResult
from app.models.normalized import NormalizedConfig, Vendor
from app.models.results import ControlResult, Status

__all__ = ["analyze", "analyze_multiple", "evaluate_controls"]


def _is_assessed(config: NormalizedConfig, results: list[ControlResult]) -> bool:
    """Legacy-score gate (replaced by posture + coverage in Phase 3).

    A confirmed vendor is always scored; an unidentified vendor only when some
    control decided PASS or FAIL from cited evidence.
    """
    return config.device.vendor != Vendor.UNKNOWN or any(r.decided for r in results)


def analyze(config: NormalizedConfig) -> ScanResult:
    """
    Evaluate all controls against a normalized config.
    Returns a ScanResult with control results, findings and a score (None when not assessed).
    """
    results = evaluate_controls(config)
    findings = [finding_from_result(r) for r in results if r.status == Status.FAIL]
    assessed = _is_assessed(config, results)

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        score=calculate_score(findings) if assessed else None,
        findings=findings,
        devices=[{
            "hostname": config.device.hostname,
            "vendor": config.device.vendor.value,
            "os_version": config.device.os_version or "unknown",
            "assessed": assessed,
        }],
        device_results=[results],
    )


def analyze_multiple(configs: list[NormalizedConfig]) -> ScanResult:
    """
    Analyze multiple configs and merge into one ScanResult.
    Used when a user uploads several config files at once.
    """
    merged = ScanResult(scan_id=str(uuid.uuid4()))
    for config in configs:
        result = analyze(config)
        merged.findings.extend(result.findings)
        merged.devices.extend(result.devices)
        merged.device_results.extend(result.device_results)

    assessed = any(d["assessed"] for d in merged.devices)
    merged.score = calculate_score(merged.findings) if assessed else None
    return merged
