"""
Remediation engine (Phase 8): deterministic, vendor-aware, verified by a full rescan.

    decisive FAIL of a control on a confirmed Cisco IOS / FortiGate configuration
      → recipe (control, vendor) from ``recipes.py``: fixed templates + validated inputs
      → edited copy of the configuration text
      → rescan the output exactly like an upload (no AI): vendor identification and parse
        coverage → parser facts, confirmed mappings, defaults → every control → posture + coverage
      → FIXED only when the control now PASSes decisively, no other control regressed,
        the vendor profile is still confirmed and parse coverage did not drop

Anything else is reported honestly and never presented as fixed: the output of a failed
verification is kept for review, a missing operator value is NEEDS_INPUT, an unsafe case is
MANUAL_REVIEW, unknown / unverified vendors are VENDOR_UNVERIFIED, and heuristic or AI
proposals are PROVISIONAL. Caller or AI text never becomes configuration.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from app.adaptive import capture_unrecognized_lines
from app.adaptive.service import AdaptiveService
from app.analysis.scoring import _control_outcome, calculate_posture
from app.controls.catalog import CONTROLS
from app.controls.evaluate import evaluate_controls
from app.facts.heuristics import generic_hostname
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
from app.models.results import DECISIVE_ASSURANCE, ControlResult, Status
from app.parsers.detector import VendorIdentification, identify_vendor
from app.remediation.recipes import INPUTS, RECIPES, Context, ManualReview, NeedsInput, parse_inputs

__all__ = [
    "RemediationStatus", "Analysis", "Check", "Outcome", "Plan", "INPUTS", "parse_inputs",
    "analyze_text", "analyze_generic_text", "remediate_control", "remediate_all",
    "generate_remediation", "apply_remediation",
]


class RemediationStatus(str, Enum):
    FIXED = "fixed"                              # generated and verified by a full rescan
    NEEDS_INPUT = "needs_input"                  # a deterministic change exists once the operator supplies values
    MANUAL_REVIEW = "manual_review"              # no known-safe deterministic change for this case
    VERIFICATION_FAILED = "verification_failed"  # generated, but the rescan did not confirm it (output kept)
    NO_RECIPE = "no_recipe"                      # no strategy for this control on this vendor
    VENDOR_UNVERIFIED = "vendor_unverified"      # unknown / unverified vendor: vendor commands are blocked
    PROVISIONAL = "provisional"                  # heuristic / AI verdict: confirm it before remediation
    NOT_FAILING = "not_failing"                  # the control has no decisive FAIL: nothing to change


@dataclass
class Analysis:
    """One configuration text scanned the way an upload is (AI off)."""
    text: str
    identification: VendorIdentification
    config: Optional[NormalizedConfig]
    results: list[ControlResult]

    @property
    def confirmed(self) -> bool:
        return self.identification.confirmed

    @property
    def vendor(self) -> Vendor:
        return self.identification.vendor

    def control(self, control_id: str) -> list[ControlResult]:
        return [r for r in self.results if r.control_id == control_id]

    def summary(self) -> dict:
        posture = calculate_posture([self.results]) if self.results else None
        coverage = self.identification.coverage
        return dict(
            posture=posture.posture if posture else None,
            coverage=posture.coverage if posture else 0,
            posture_bounds=list(posture.bounds) if posture and posture.bounds else None,
            critical_unassessed=posture.critical_unassessed if posture else [],
            vendor_status=self.identification.status,
            parse_coverage=round(coverage.ratio, 3) if coverage else None,
            uncovered_lines=coverage.uncovered_count if coverage else 0,
        )


def analyze_text(text: str) -> Analysis:
    identification = identify_vendor(text)
    if not identification.confirmed:
        return Analysis(text, identification, None, [])
    config = identification.config
    capture_unrecognized_lines(config)
    # confirmed learned mappings apply as in a scan; the AI is never consulted here
    AdaptiveService(ai_available=lambda: False).process(config, use_ai=False, report_unresolved=False)
    return Analysis(text, identification, config, evaluate_controls(config))


def analyze_generic_text(text: str) -> Analysis:
    """One configuration text read the way an *unknown-vendor* upload is (tokenizer, confirmed
    recognizers, learned mappings, lexicon heuristics; the AI is never consulted).

    Used to re-read a candidate remediation applied to a copy of an unconfirmed-vendor
    configuration: no vendor parser, no vendor defaults, absence never evidence.
    """
    identification = identify_vendor(text)
    lines = text.splitlines()
    config = NormalizedConfig(
        device=DeviceInfo(vendor=Vendor.UNKNOWN, hostname=generic_hostname(lines) or "unknown"),
        raw_config=text, raw_lines=lines,
    )
    capture_unrecognized_lines(config)
    AdaptiveService(ai_available=lambda: False).process(config, use_ai=False, report_unresolved=False)
    return Analysis(text, identification, config, evaluate_controls(config))


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class Outcome:
    control_id: str
    status: RemediationStatus
    reason: str
    hostname: str = "unknown"
    vendor: str = "unknown"
    explanation: str = ""
    warnings: list[str] = field(default_factory=list)
    # what the remediation is about: the failing scopes and their cited lines (before state)
    scopes: list[str] = field(default_factory=list)
    evidence: list[tuple[int, str]] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    missing_inputs: list[str] = field(default_factory=list)
    control_status_before: Optional[str] = None
    control_status_after: Optional[str] = None
    # the proposed deterministic change as a unified diff
    diff: str = ""
    checks: list[Check] = field(default_factory=list)
    before: Optional[dict] = None
    after: Optional[dict] = None
    # generated configuration (after state), kept for review even when verification failed
    fixed_config: Optional[str] = None


def _join(lines: list[str], like: str) -> str:
    newline = "\r\n" if "\r\n" in like else "\n"
    return newline.join(lines) + (newline if like.endswith(("\n", "\r")) else "")


def _collapsed(results: list[ControlResult]) -> str:
    if not results:
        return "missing"
    outcome, _ = _control_outcome(results)
    return outcome


def _status_text(results: list[ControlResult]) -> Optional[str]:
    return "/".join(dict.fromkeys(r.status.value for r in results)) or None


def verify(before: Analysis, after: Analysis, control_id: Optional[str]) -> list[Check]:
    """Rescan checks. ``control_id`` None checks only vendor, coverage and regressions (a whole plan)."""
    same_vendor = after.confirmed and after.vendor == before.vendor
    checks = [Check(
        "vendor", same_vendor,
        f"Still confirmed as {before.vendor.value}" if same_vendor else
        f"The generated configuration is no longer confirmed as {before.vendor.value} "
        f"({after.identification.status}: {after.identification.reason or 'vendor not detected'})",
    )]
    if not same_vendor:
        checks.append(Check("controls", False, "Controls were not re-evaluated: the vendor profile was lost"))
        return checks

    old_cov, new_cov = before.identification.coverage, after.identification.coverage
    coverage_ok = (new_cov.uncovered_count <= old_cov.uncovered_count
                   and new_cov.longest_foreign_run <= old_cov.longest_foreign_run)
    checks.append(Check(
        "parse_coverage", coverage_ok,
        f"Parse coverage {old_cov.ratio:.0%} → {new_cov.ratio:.0%}, lines outside the grammar "
        f"{old_cov.uncovered_count} → {new_cov.uncovered_count}",
    ))

    if control_id is not None:
        target = after.control(control_id)
        passed = bool(target) and all(r.status == Status.PASS and r.assurance in DECISIVE_ASSURANCE for r in target)
        checks.append(Check(
            "target", passed,
            f"{control_id} now passes: {target[0].reason}" if passed else
            f"{control_id} is {_status_text(target)} after the change: "
            + "; ".join(dict.fromkeys(r.reason for r in target)),
        ))

    checks.append(no_regression(before, after, control_id))
    return checks


def no_regression(before: Analysis, after: Analysis, control_id: Optional[str]) -> Check:
    """Every control other than the target: none went from decided-pass to anything else, or got a new FAIL."""
    regressions = []
    for other in CONTROLS:
        if other == control_id:
            continue
        old, new = before.control(other), after.control(other)
        old_outcome, new_outcome = _collapsed(old), _collapsed(new)
        old_fails = sum(r.status == Status.FAIL for r in old)
        new_fails = sum(r.status == Status.FAIL for r in new)
        if (old_outcome == "pass" and new_outcome != "pass") or (
                new_outcome == "fail" and (old_outcome != "fail" or new_fails > old_fails)):
            regressions.append(f"{other} {old_outcome} → {new_outcome}")
    return Check("no_regression", not regressions,
                 "No other control got worse" if not regressions else "Regressed: " + ", ".join(regressions))


def remediate_control(text: str, control_id: str, inputs: dict,
                      before: Optional[Analysis] = None) -> tuple[Outcome, Optional[Analysis]]:
    """Remediate one control on one configuration. Returns the outcome and the verified rescan (FIXED only)."""
    before = before or analyze_text(text)
    control = CONTROLS[control_id]
    config = before.config
    outcome = Outcome(control_id, RemediationStatus.NOT_FAILING, "",
                      hostname=config.device.hostname if config else "unknown", vendor=before.vendor.value)
    if not before.confirmed:
        outcome.status = RemediationStatus.VENDOR_UNVERIFIED
        outcome.reason = ("Vendor-specific remediation is blocked: the vendor is "
                          f"{before.identification.status}" + (f" ({before.identification.reason})"
                                                               if before.identification.reason else "")
                          + ". Follow the vendor-neutral recommendation.")
        return outcome, None

    results = before.control(control_id)
    outcome.control_status_before = _status_text(results)
    outcome.before = before.summary()
    fails = [r for r in results if r.status == Status.FAIL and r.assurance in DECISIVE_ASSURANCE]
    if not fails:
        if any(r.status == Status.FAIL or r.proposed_status for r in results):
            outcome.status = RemediationStatus.PROVISIONAL
            outcome.reason = "Only a provisional (heuristic or AI) verdict exists: confirm it before remediation"
        else:
            outcome.reason = f"{control_id} has no decisive FAIL ({outcome.control_status_before}): nothing to change"
        return outcome, None

    outcome.scopes = [r.scope for r in fails if r.scope]
    outcome.evidence = list(dict.fromkeys((n, t) for r in fails for n, t in zip(r.evidence.line_numbers, r.evidence.text)))
    recipe = RECIPES.get((control_id, before.vendor))
    if recipe is None:
        outcome.status = RemediationStatus.NO_RECIPE
        outcome.reason = (f"No deterministic {before.vendor.value} remediation exists for {control_id} "
                          f"({control.title}); follow the recommendation")
        return outcome, None

    outcome.explanation, outcome.warnings, outcome.inputs = recipe.explanation, list(recipe.warnings), list(recipe.inputs)
    lines = text.splitlines()
    try:
        new_lines = recipe.build(Context(lines, config, fails, inputs))
    except NeedsInput as e:
        outcome.status, outcome.missing_inputs = RemediationStatus.NEEDS_INPUT, e.names
        outcome.reason = f"Provide {', '.join(INPUTS[n].label for n in e.names)} to generate this change"
        return outcome, None
    except ManualReview as e:
        # nothing was generated: the recipe's description of its change would contradict the status
        outcome.status, outcome.reason = RemediationStatus.MANUAL_REVIEW, str(e)
        outcome.explanation, outcome.warnings = "", []
        return outcome, None

    new_text = _join(new_lines, text)
    outcome.fixed_config = new_text
    outcome.diff = "\n".join(difflib.unified_diff(lines, new_lines, "before", "after", n=2, lineterm=""))
    if new_lines == lines:
        outcome.status = RemediationStatus.VERIFICATION_FAILED
        outcome.reason = "The recipe found nothing to change for the failing scopes"
        return outcome, None

    after = analyze_text(new_text)
    outcome.after = after.summary()
    outcome.control_status_after = _status_text(after.control(control_id)) if after.confirmed else None
    outcome.checks = verify(before, after, control_id)
    failed = [c.detail for c in outcome.checks if not c.passed]
    if failed:
        outcome.status = RemediationStatus.VERIFICATION_FAILED
        outcome.reason = "Verification failed: " + "; ".join(failed)
        return outcome, None
    outcome.status = RemediationStatus.FIXED
    outcome.reason = next(c.detail for c in outcome.checks if c.name == "target")
    return outcome, after


@dataclass
class Plan:
    hostname: str
    vendor: str
    vendor_status: str
    outcomes: list[Outcome]
    before: dict
    after: dict
    checks: list[Check]
    # every verified change applied in sequence; None when nothing was fixed
    fixed_config: Optional[str]

    @property
    def fixed_controls(self) -> list[str]:
        return [o.control_id for o in self.outcomes if o.status == RemediationStatus.FIXED]


def credit_earlier_fix(outcome: Outcome, current: Analysis, outcomes: list[Outcome]) -> Outcome:
    """A control that failed at the start of a plan but no longer fails on the text an earlier step produced.

    It is FIXED only when every result for it is now PASS (or N/A): the combined file resolves it and the plan's
    own rescan shows that. Anything short of that (NOT_CONFIGURED, UNKNOWN) keeps NOT_FAILING -absence is
    never a pass."""
    results = current.control(outcome.control_id)
    if (outcome.status != RemediationStatus.NOT_FAILING or not results
            or not all(r.status in (Status.PASS, Status.N_A) for r in results)):
        return outcome
    by = [o.control_id for o in outcomes if o.status == RemediationStatus.FIXED]
    outcome.status = RemediationStatus.FIXED
    outcome.reason = (f"{outcome.control_id} now passes: an earlier fix in this plan resolved it"
                      + (f" ({', '.join(by)})" if by else ""))
    return outcome


def remediate_all(text: str, inputs: dict, skip: frozenset[str] | set[str] = frozenset()) -> Plan:
    """Remediate every failing control in catalog order; each step is verified against the previous text.

    ``skip``: controls the caller knows to be provisional (e.g. an AI proposal in the stored scan) -never changed.
    """
    original = current = analyze_text(text)
    outcomes = []
    if original.confirmed:
        failing = [c for c in CONTROLS if c in skip or any(r.status == Status.FAIL or r.proposed_status
                                                           for r in original.control(c))]
        for control_id in failing:
            if control_id in skip:
                outcomes.append(Outcome(control_id, RemediationStatus.PROVISIONAL,
                                        "Only a provisional (heuristic or AI) verdict exists: confirm it before remediation",
                                        hostname=original.config.device.hostname, vendor=original.vendor.value))
                continue
            outcome, after = remediate_control(current.text, control_id, inputs, before=current)
            if after is not None:
                current = after
            outcome = credit_earlier_fix(outcome, current, outcomes)
            if outcome.status == RemediationStatus.FIXED:
                outcome.fixed_config = None  # the plan keeps one combined output
            outcomes.append(outcome)
    changed = current is not original
    return Plan(
        hostname=original.config.device.hostname if original.config else "unknown",
        vendor=original.vendor.value,
        vendor_status=original.identification.status,
        outcomes=outcomes,
        before=original.summary(),
        after=current.summary(),
        checks=verify(original, current, None) if changed else [],
        fixed_config=current.text if changed else None,
    )


# ── compatibility shims ─────────────────────────────────────────────────────
# Kept so existing scripts importing the pre-Phase 8 API (e.g. the repository's verify_fix.py and
# backend/diagnose_remediation.py) still run. They route through the verified engine; command text
# passed in is never applied.

def generate_remediation(finding, configs: list[NormalizedConfig]) -> dict:
    """DEPRECATED: the verified change for the finding's control as a diff, plus its status."""
    config = next((c for c in configs if c.device.hostname == finding.device_hostname), configs[0])
    outcome, _ = remediate_control(config.raw_config, finding.rule_id, {})
    return {
        "commands": outcome.diff or f"! {outcome.status.value}: {outcome.reason}",
        "explanation": outcome.explanation or outcome.reason,
        "status": outcome.status.value,
    }


def apply_remediation(config: NormalizedConfig, commands: str = "") -> NormalizedConfig:
    """DEPRECATED: ``commands`` is ignored. Applies every verified change and returns the re-parsed config."""
    if config.device.vendor not in (Vendor.CISCO_IOS, Vendor.FORTINET):
        raise ValueError(f"Remediation requires a confirmed vendor profile (got '{config.device.vendor.value}')")
    plan = remediate_all(config.raw_config, {})
    if plan.fixed_config is None:
        return config
    return identify_vendor(plan.fixed_config).config or config
