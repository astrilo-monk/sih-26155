"""
Control evaluation engine.

Runs every catalog control against a normalized config. Each control yields
ControlResults (PASS / FAIL / NOT_CONFIGURED / UNKNOWN / N_A); Findings are
the view of the FAIL results, and the legacy score is computed from them.
"""

from __future__ import annotations

import logging
import uuid

from app.analysis.rules.boundary import BOUNDARY_RULES
from app.analysis.rules.crypto import CRYPTO_RULES
from app.analysis.rules.logging_rules import LOGGING_RULES
from app.analysis.rules.management import MANAGEMENT_RULES
from app.analysis.scoring import calculate_score
from app.controls.views import finding_from_result
from app.models.findings import ScanResult
from app.models.normalized import NormalizedConfig, Vendor
from app.models.results import ControlResult, Status

logger = logging.getLogger(__name__)

ALL_RULES = MANAGEMENT_RULES + BOUNDARY_RULES + LOGGING_RULES + CRYPTO_RULES


def evaluate_controls(config: NormalizedConfig) -> list[ControlResult]:
    """Results of every control for one config (a broken rule yields UNKNOWN, never a crash)."""
    results: list[ControlResult] = []
    for rule in ALL_RULES:
        try:
            results.extend(rule.evaluate(config))
        except Exception as e:
            logger.warning("Control %s failed: %s", rule.rule_id, e)
            results.append(ControlResult(
                control_id=rule.rule_id,
                status=Status.UNKNOWN,
                reason=f"The control could not be evaluated: {e}",
                device_hostname=config.device.hostname,
                vendor=config.device.vendor.value,
            ))
    return results


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
