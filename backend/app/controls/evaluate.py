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
   * else nothing  → NOT_CONFIGURED, or UNKNOWN for relational controls

No vendor decides whether a control runs.
"""

from __future__ import annotations

import logging

from app.controls.catalog import CONTROLS, Control, ControlKind
from app.controls.judges import JUDGES
from app.facts.defaults import default_facts
from app.facts.from_normalized import PARSER_COVERAGE, facts_from_config, weakest
from app.facts.predicates import SecurityFact
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

    results: list[ControlResult] = []
    for control in CONTROLS.values():
        try:
            results.extend(evaluate_control(control, facts, config))
        except Exception as e:
            logger.warning("Control %s failed: %s", control.control_id, e)
            results.append(_result(config, control, Status.UNKNOWN, f"The control could not be evaluated: {e}"))
    return results


def evaluate_control(control: Control, facts: list[SecurityFact], config: NormalizedConfig) -> list[ControlResult]:
    vendor = config.device.vendor
    needed = [f for f in facts if f.predicate in control.needs]
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
            _result(config, control, Status.FAIL, o.reason, [fact, *o.also], scope=fact.scope, failure=o.failure)
            for fact, o in fails
        ]

    for status in (Status.UNKNOWN, Status.PASS):
        group = [(fact, o) for fact, o in judged if o.status == status]
        if not group:
            continue
        cited = [f for fact, o in group for f in (fact, *o.also)]
        reason = "; ".join(dict.fromkeys(o.reason for _, o in group))
        if status == Status.PASS:
            if any(f.assurance == Assurance.DEFAULT for f in cited):
                reason += f" ({'; '.join(dict.fromkeys(f.provenance for f in cited if f.assurance == Assurance.DEFAULT))})"
            elif not any(f.evidence for f in cited):
                return [_result(config, control, Status.UNKNOWN,
                                f"{reason}, but no configuration line supports it", cited, assured=False)]
        return [_result(config, control, status, reason, cited, assured=status == Status.PASS)]

    if control.kind == ControlKind.RELATIONAL:
        return [_result(config, control, Status.UNKNOWN, "No relevant setting was found in this configuration")]
    return [_result(config, control, Status.NOT_CONFIGURED, "No relevant setting was found in this configuration")]


def _result(config, control, status, reason, facts=(), scope=None, failure=None, assured=True) -> ControlResult:
    facts = list(facts)
    numbers = list(dict.fromkeys(n for f in facts for n in f.evidence.line_numbers))
    raw = config.raw_lines
    decided = status in (Status.PASS, Status.FAIL)
    return ControlResult(
        control_id=control.control_id,
        status=status,
        reason=reason,
        device_hostname=config.device.hostname,
        vendor=config.device.vendor.value,
        assurance=weakest(f.assurance for f in facts) if decided and assured else None,
        scope=scope,
        evidence=Evidence(line_numbers=numbers, text=[raw[n - 1] for n in numbers]),
        facts=facts,
        failure=failure,
    )
