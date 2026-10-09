"""
Generic control evaluator.

For every catalog control, over the security facts of one config:

1. take the facts whose predicate the control ``needs``
2. none found, confirmed vendor:
   * a needed predicate its parser does not read → UNKNOWN
   * otherwise the vendor's documented defaults (assurance DEFAULT)
3. judge every fact, then combine:
   * any FAIL      → one FAIL per failing fact (scope)
   * else UNKNOWN  → UNKNOWN citing the undecidable facts
   * else PASS     → PASS citing every passing fact (needs a cited line unless DEFAULT)
   * else nothing  → N_A for an optional feature a confirmed vendor's parser found none of,
     UNKNOWN for relational controls, otherwise NOT_CONFIGURED

No vendor decides whether a control runs.
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

from app.adaptive.context import structural_paths
from app.controls.catalog import CONTROLS, Control, ControlKind
from app.controls.judges import JUDGES
from app.facts.defaults import default_facts
from app.facts.from_normalized import PARSER_COVERAGE, facts_from_config, weakest
from app.facts.predicates import NOT_SET, SecurityFact
from app.models.normalized import NormalizedConfig
from app.models.results import Assurance, ControlResult, Evidence, Status

logger = logging.getLogger(__name__)


def evaluate_controls(config: NormalizedConfig, extra_recognizers=()) -> list[ControlResult]:
    """Results of every control for one config (a broken control yields UNKNOWN, never a crash)."""
    try:
        facts = facts_from_config(config, extra_recognizers)
    except Exception as e:
        logger.warning("Fact extraction failed: %s", e)
        return [_result(config, c, Status.UNKNOWN, f"Facts could not be extracted: {e}") for c in CONTROLS.values()]

    profile = platform_profile(config.raw_lines)
    results: list[ControlResult] = []
    for control in CONTROLS.values():
        try:
            answer = evaluate_control(control, facts, config)
        except Exception as e:
            logger.warning("Control %s failed: %s", control.control_id, e)
            answer = [_result(config, control, Status.UNKNOWN, f"The control could not be evaluated: {e}")]
        if profile and control.control_id in profile["not_applicable"] and all(
                r.status in (Status.UNKNOWN, Status.NOT_CONFIGURED) for r in answer):
            # the platform cannot have this setting: an undecided answer is really "does not apply"
            answer = [_result(config, control, Status.N_A, profile["reason"])]
        results.extend(answer)
    return results


def platform_profile(raw_lines: list[str]) -> Optional[dict]:
    """The profile (backend/data/platform_profiles.json) every top-level statement of this configuration belongs
    to. Only top-level lines count: a Terraform ``ingress { … }`` sits inside its ``resource``."""
    statements = [line.strip() for line, path in zip(raw_lines, structural_paths(raw_lines)) if line.strip() and not path]
    if not statements:
        return None
    return next((p for p in _profiles()
                 if all(s.split(None, 1)[0] in p.get("roots", [p.get("root")]) for s in statements)), None)


@lru_cache(maxsize=1)
def _profiles() -> tuple[dict, ...]:
    path = Path(__file__).resolve().parents[2] / "data" / "platform_profiles.json"
    try:
        return tuple(json.loads(path.read_text(encoding="utf-8"))["profiles"])
    except (OSError, ValueError, KeyError) as e:
        logger.warning("Platform profiles unavailable: %s", e)
        return ()


def evaluate_control(control: Control, facts: list[SecurityFact], config: NormalizedConfig) -> list[ControlResult]:
    vendor = config.device.vendor
    # a fact bound to one control (an AI judge answer) is never read by another
    needed = [f for f in facts if f.predicate in control.needs and f.control_id in (None, control.control_id)]
    if not needed and vendor in PARSER_COVERAGE:
        unread = sorted(set(control.needs) - PARSER_COVERAGE[vendor])
        if unread:
            return [_result(config, control, Status.UNKNOWN,
                            f"The {vendor.value} parser does not read {', '.join(unread)}")]
        needed = default_facts(vendor, control.needs)

    judge = JUDGES[control.control_id]
    judged = [(fact, outcome) for fact in needed if (outcome := judge(fact, needed, vendor)) is not None]

    fails = [(fact, o) for fact, o in judged if o.status == Status.FAIL]
    if fails:
        return [
            _result(config, control, Status.FAIL, _unstated(o.reason, fact), [fact, *o.also], scope=fact.scope,
                    failure=o.failure)
            for fact, o in fails
        ]

    for status in (Status.UNKNOWN, Status.PASS):
        group = [(fact, o) for fact, o in judged if o.status == status]
        if not group:
            continue
        cited = [f for fact, o in group for f in (fact, *o.also)]
        reason = "; ".join(dict.fromkeys(o.reason for _, o in group))
        ai_pass = [(fact, o) for fact, o in judged if o.status == Status.PASS and fact.control_id == control.control_id]
        if status == Status.UNKNOWN and ai_pass:
            # The AI judge answered what the lexicon could not decide: still UNKNOWN, a PASS awaiting confirmation
            cited += [f for fact, o in ai_pass for f in (fact, *o.also)]
            reason = (f"AI proposes PASS, awaiting confirmation: {'; '.join(dict.fromkeys(o.reason for _, o in ai_pass))}"
                      f" (undecided: {reason})")
            return [_result(config, control, status, reason, cited, assured=False, proposed=Status.PASS)]
        if status == Status.PASS:
            if any(f.assurance == Assurance.DEFAULT for f in cited):
                reason += f" ({'; '.join(dict.fromkeys(f.provenance for f in cited if f.assurance == Assurance.DEFAULT))})"
            elif not any(f.evidence for f in cited):
                return [_result(config, control, Status.UNKNOWN,
                                f"{reason}, but no configuration line supports it", cited, assured=False)]
        return [_result(config, control, status, reason, cited, assured=status == Status.PASS)]

    if control.optional_feature and vendor in PARSER_COVERAGE:
        # Its parser reads the feature and found none of it: the question does not arise on this device
        return [_result(config, control, Status.N_A,
                        f"This device does not configure {control.optional_feature}, "
                        "so the control does not apply")]
    if control.kind == ControlKind.RELATIONAL:
        return [_result(config, control, Status.UNKNOWN, "No relevant setting was found in this configuration")]
    return [_result(config, control, Status.NOT_CONFIGURED, "No relevant setting was found in this configuration")]


def _unstated(reason: str, fact: SecurityFact) -> str:
    """A failure read from absence says how the configuration would have stated the setting, and one read from a
    vendor default names that default and its source."""
    absent = fact.value is NOT_SET and fact.assurance == Assurance.CONFIRMED
    if (absent or fact.assurance == Assurance.DEFAULT) and fact.provenance and fact.provenance not in reason:
        return f"{reason} ({fact.provenance[0].upper()}{fact.provenance[1:]}.)"
    return reason


def _result(config, control, status, reason, facts=(), scope=None, failure=None, assured=True,
            proposed=None) -> ControlResult:
    facts = list(facts)
    numbers = list(dict.fromkeys(n for f in facts for n in f.evidence.line_numbers))
    raw = config.raw_lines
    decided = status in (Status.PASS, Status.FAIL)
    note = config.ai_notes.get(control.control_id) if status == Status.UNKNOWN and not proposed else None
    assurance = Assurance.AI_VERIFIED if proposed else weakest(f.assurance for f in facts) if decided and assured else None
    if assurance == Assurance.AI_VERIFIED and decided:
        # An AI verdict is a proposal: undecided (never scored, counted or remediated) until a human confirms it
        status, proposed, failure = Status.UNKNOWN, status, None
        reason = f"AI proposes {proposed.value.upper()}, awaiting confirmation: {reason}"
    return ControlResult(
        control_id=control.control_id,
        status=status,
        reason=f"{reason} (AI: {note})" if note else reason,
        device_hostname=config.device.hostname,
        vendor=config.device.vendor.value,
        assurance=assurance,
        proposed_status=proposed,
        scope=scope,
        evidence=Evidence(line_numbers=numbers, text=[raw[n - 1] for n in numbers]),
        facts=facts,
        failure=failure,
    )
