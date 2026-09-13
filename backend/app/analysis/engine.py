"""
Security analysis engine.

Runs all detection rules against a normalized config and
produces a ScanResult with findings and a security score.
"""

from __future__ import annotations
import uuid
from app.models.normalized import NormalizedConfig, Vendor
from app.models.findings import ScanResult, Finding
from app.analysis.rules.management import MANAGEMENT_RULES
from app.analysis.rules.boundary import BOUNDARY_RULES
from app.analysis.rules.logging_rules import LOGGING_RULES
from app.analysis.rules.crypto import CRYPTO_RULES
from app.analysis.scoring import calculate_score


ALL_RULES = MANAGEMENT_RULES + BOUNDARY_RULES + LOGGING_RULES + CRYPTO_RULES

# INTERIM(phase1)
ABSENCE_BASED_RULE_IDS = tuple(rule.rule_id for rule in ALL_RULES if rule.absence_based)


def has_assessable_evidence(config: NormalizedConfig, findings: list[Finding]) -> bool:
    """
    INTERIM(phase1): whether any rule evaluated real evidence from this config.

    A parser-read vendor always qualifies. For an unidentified vendor the
    rules only see values the adaptive layer applied; unless a rule actually
    evaluated one of those values (or failed), the config was not assessed and
    must not be shown as a clean score. Replaced by Phase 2/3 results and coverage.
    """
    if config.device.vendor != Vendor.UNKNOWN or findings:
        return True
    applied = {m.normalized_field for m in config.ai_mappings if m.applied}
    return any(applied & rule.evaluated_fields(config) for rule in ALL_RULES)


def analyze(config: NormalizedConfig) -> ScanResult:
    """
    Run all security rules against a normalized config.
    Returns a ScanResult with all findings and a score (None when not assessed).
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

    assessed = has_assessable_evidence(config, findings)

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

    assessed = any(d["assessed"] for d in all_devices)
    score = calculate_score(all_findings) if assessed else None

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        score=score,
        findings=all_findings,
        devices=all_devices,
    )
