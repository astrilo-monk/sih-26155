"""
Security analysis engine.

Runs all detection rules against a normalized config and
produces a ScanResult with findings and a security score.
"""

from __future__ import annotations
import uuid
from app.models.normalized import NormalizedConfig
from app.models.findings import ScanResult, Finding
from app.analysis.rules.management import MANAGEMENT_RULES
from app.analysis.rules.boundary import BOUNDARY_RULES
from app.analysis.rules.logging_rules import LOGGING_RULES
from app.analysis.rules.crypto import CRYPTO_RULES
from app.analysis.scoring import calculate_score


ALL_RULES = MANAGEMENT_RULES + BOUNDARY_RULES + LOGGING_RULES + CRYPTO_RULES


def analyze(config: NormalizedConfig) -> ScanResult:
    """
    Run all security rules against a normalized config.
    Returns a ScanResult with all findings and a score.
    """
    findings: list[Finding] = []

    for rule in ALL_RULES:
        try:
            rule_findings = rule.evaluate(config)
            findings.extend(rule_findings)
        except Exception as e:
            # A single broken rule shouldn't kill the entire scan.
            # In production we'd log this properly.
            print(f"Warning: Rule {rule.rule_id} failed: {e}")

    score = calculate_score(findings)

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        score=score,
        findings=findings,
        devices=[{
            "hostname": config.device.hostname,
            "vendor": config.device.vendor.value,
            "os_version": config.device.os_version or "unknown",
        }],
    )


def analyze_multiple(configs: list[NormalizedConfig]) -> ScanResult:
    """
    Analyze multiple configs and merge into one ScanResult.
    Used when a user uploads several config files at once.
    """
    all_findings: list[Finding] = []
    all_devices: list[dict] = []

    for config in configs:
        result = analyze(config)
        all_findings.extend(result.findings)
        all_devices.extend(result.devices)

    score = calculate_score(all_findings)

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        score=score,
        findings=all_findings,
        devices=all_devices,
    )
