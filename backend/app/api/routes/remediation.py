"""
Remediation API routes (Phase 8).

Every route works from a stored scan. For a **confirmed** vendor the deterministic
engine in ``app.remediation.engine`` does the work: a remediation runs only for a
decisive FAIL, is generated from a fixed recipe, and is reported FIXED only after a
full rescan verified it. No request field carries command text on that path.

For an **unconfirmed** vendor there is no recipe and no trusted grammar, so
``/remediation/candidate*`` offers the reviewed alternative: command text an
administrator typed or the AI proposed, validated and (where a deterministic effect
can be derived) simulated on a copy of the configuration, and confirmed by a human.
A candidate never becomes a fix, never changes the stored scan and is never executed:
see ``app.remediation.candidates``.
"""

from __future__ import annotations

import io
import zipfile
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.ai.client import is_available
from app.ai.redaction import Redactor
from app.ai.remediation import propose_candidate
from app.api.routes.scan import (
    _device_results, config_redactor, display_scrub, get_scan_store, redact_config_text, redact_lines,
)
from app.api.schemas import (
    DeviceRemediationPlanSchema, DownloadFixedRequest, EvidenceSchema, PostureSummarySchema,
    RemediationCandidateRequest, RemediationCandidateSchema, RemediationCheckSchema, RemediationInputSchema,
    RemediationPlanRequest, RemediationPlanResponse, RemediationRequest, RemediationResponse,
)
from app.controls.catalog import CONTROLS
from app.models.normalized import Vendor
from app.models.results import DECISIVE_ASSURANCE, Status
from app.remediation import candidates as cand
from app.remediation.engine import (
    INPUTS, Outcome, RemediationStatus, parse_inputs, remediate_all, remediate_control,
)

router = APIRouter()


def _stored(scan_id: str) -> dict:
    stored = get_scan_store().get(scan_id)
    if not stored:
        raise HTTPException(404, "Scan not found")
    if not stored.get("configs"):
        raise HTTPException(400, "No configs available")
    return stored


def _inputs(raw: dict) -> dict:
    values, errors = parse_inputs(raw)
    if errors:
        raise HTTPException(422, {"message": "Invalid remediation inputs", "errors": errors})
    return values


def _confirmed(stored: dict, index: int) -> bool:
    identifications = stored.get("identifications")
    if identifications and identifications[index] is not None and not identifications[index].confirmed:
        return False
    return stored["configs"][index].device.vendor in (Vendor.CISCO_IOS, Vendor.FORTINET)


def _index(stored: dict, device_hostname: str, config_index: Optional[int]) -> int:
    """The config a request is about. ``config_index`` is the identity; a hostname is display metadata."""
    configs = stored["configs"]
    if config_index is not None:
        if not 0 <= config_index < len(configs) or configs[config_index].device.hostname != device_hostname:
            raise HTTPException(404, "Device not found in scan")
        return config_index
    matches = [i for i, c in enumerate(configs) if c.device.hostname == device_hostname]
    if not matches:
        raise HTTPException(404, "Device not found in scan")
    if len(matches) > 1:
        raise HTTPException(409, f"{len(matches)} configs in this scan are named '{device_hostname}': "
                                 "pass config_index to choose one")
    return matches[0]


def _gate(stored: dict, index: int, control_id: str) -> Optional[Outcome]:
    """What the stored scan (the results the user saw) says before any recipe runs."""
    config = stored["configs"][index]
    base = dict(hostname=config.device.hostname, vendor=config.device.vendor.value)
    if not _confirmed(stored, index):
        identification = (stored.get("identifications") or [None] * (index + 1))[index]
        detail = f" ({identification.reason})" if identification is not None and identification.reason else ""
        return Outcome(control_id, RemediationStatus.VENDOR_UNVERIFIED,
                       f"Vendor-specific remediation is blocked: the vendor is unknown or unverified{detail}. "
                       "Follow the vendor-neutral recommendation.", **base)
    results = [r for r in _device_results(stored.get("result"), stored["configs"], index) if r.control_id == control_id]
    decisive = any(r.status == Status.FAIL and r.assurance in DECISIVE_ASSURANCE for r in results)
    if not decisive and any(r.status == Status.FAIL or r.proposed_status for r in results):
        return Outcome(control_id, RemediationStatus.PROVISIONAL,
                       "Only a provisional (heuristic or AI) verdict exists: confirm it before remediation", **base)
    return None


def _provisional(stored: dict, index: int) -> dict[str, Outcome]:
    """Controls of a confirmed-vendor device whose stored verdict is only provisional: never remediated."""
    return {c: gate for c in CONTROLS if (gate := _gate(stored, index, c)) is not None}


def _summary(summary: Optional[dict]) -> Optional[PostureSummarySchema]:
    return PostureSummarySchema(**summary) if summary else None


def _checks(checks) -> list[RemediationCheckSchema]:
    return [RemediationCheckSchema(name=c.name, passed=c.passed, detail=c.detail) for c in checks]


def _input_schema(name: str) -> RemediationInputSchema:
    spec = INPUTS[name]
    return RemediationInputSchema(name=spec.name, label=spec.label, help=spec.help)


def _redactor(stored: dict, inputs: dict, index: int) -> Redactor:
    """Knows this config's secrets and any secret the operator typed (the NTP key)."""
    redactor = config_redactor([stored["configs"][index]])
    redactor.add_secret(inputs.get("ntp_key"))
    return redactor


def _response(outcome: Outcome, index: int, redactor: Redactor) -> RemediationResponse:
    """What the browser sees: every configuration quote redacted. /download-fixed alone returns the real file."""
    numbers, lines = zip(*outcome.evidence) if outcome.evidence else ((), ())

    def scrub(text):
        return display_scrub(redactor, text)
    return RemediationResponse(
        rule_id=outcome.control_id,
        title=CONTROLS[outcome.control_id].title,
        device_hostname=outcome.hostname,
        vendor=outcome.vendor,
        config_index=index,
        status=outcome.status.value,
        reason=scrub(outcome.reason),
        explanation=scrub(outcome.explanation),
        warnings=[scrub(w) for w in outcome.warnings],
        scopes=[scrub(s) for s in outcome.scopes],
        evidence=EvidenceSchema(line_numbers=list(numbers), lines=redact_lines(redactor, lines)),
        required_inputs=[_input_schema(n) for n in outcome.inputs],
        missing_inputs=outcome.missing_inputs,
        control_status_before=outcome.control_status_before,
        control_status_after=outcome.control_status_after,
        diff="\n".join(redact_lines(redactor, outcome.diff.split("\n"))) if outcome.diff else "",
        checks=_checks(outcome.checks),
        before=_summary(outcome.before),
        after=_summary(outcome.after),
        fixed_config=redact_config_text(redactor, outcome.fixed_config),
    )


@router.post("/remediate", response_model=RemediationResponse)
async def remediate_finding(req: RemediationRequest):
    """Generate and verify the deterministic remediation of one control on one device."""
    stored = _stored(req.scan_id)
    if req.rule_id not in CONTROLS:
        raise HTTPException(404, f"Unknown control '{req.rule_id}'")
    index = _index(stored, req.device_hostname, req.config_index)
    inputs = _inputs(req.inputs)

    outcome = _gate(stored, index, req.rule_id)
    if outcome is None:
        outcome, _ = remediate_control(stored["configs"][index].raw_config, req.rule_id, inputs)
    return _response(outcome, index, _redactor(stored, inputs, index))


def _device_plan(stored: dict, index: int, inputs: dict) -> DeviceRemediationPlanSchema:
    config = stored["configs"][index]
    redactor = _redactor(stored, inputs, index)
    if not _confirmed(stored, index):
        results = _device_results(stored.get("result"), stored["configs"], index)
        flagged = [c for c in CONTROLS if any(r.control_id == c and (r.status == Status.FAIL or r.proposed_status)
                                              for r in results)]
        identification = (stored.get("identifications") or [None] * (index + 1))[index]
        return DeviceRemediationPlanSchema(
            config_index=index, device_hostname=config.device.hostname, vendor=config.device.vendor.value,
            vendor_status=identification.status if identification is not None else "unknown",
            remediations=[_response(_gate(stored, index, c), index, redactor) for c in flagged],
            candidates=[_candidate_schema(stored, item) for item in _candidates(stored).values()
                        if item.config_index == index],
        )
    gates = _provisional(stored, index)
    plan = remediate_all(config.raw_config, inputs, skip=set(gates))
    remediations = [_response(gates.get(o.control_id, o), index, redactor) for o in plan.outcomes]
    return DeviceRemediationPlanSchema(
        config_index=index, device_hostname=plan.hostname, vendor=plan.vendor, vendor_status=plan.vendor_status,
        remediations=remediations, fixed_controls=plan.fixed_controls, checks=_checks(plan.checks),
        before=_summary(plan.before), after=_summary(plan.after),
        fixed_config=redact_config_text(redactor, plan.fixed_config),
    )


@router.post("/remediation/plan", response_model=RemediationPlanResponse)
async def remediation_plan(req: RemediationPlanRequest):
    """Remediate every failing control of every device; each change verified by a rescan."""
    stored = _stored(req.scan_id)
    inputs = _inputs(req.inputs)
    return RemediationPlanResponse(
        scan_id=req.scan_id,
        inputs=[_input_schema(n) for n in INPUTS],
        devices=[_device_plan(stored, i, inputs) for i in range(len(stored["configs"]))],
    )


# -- candidate remediation (unconfirmed vendors) ------------------------------
# A candidate is command text from outside the engine (typed by an administrator, or proposed by the
# AI). It is validated, simulated on a copy where a deterministic effect can be derived, and confirmed
# by a human. It never changes the stored scan, never enters a download and is never executed.

def _candidates(stored: dict) -> dict[str, cand.Candidate]:
    """This scan's candidates, keyed by config_index-control. Per scan only: nothing is persisted."""
    return stored.setdefault("candidates", {})


def _fails(stored: dict, index: int, control_id: str) -> list:
    results = _device_results(stored.get("result"), stored["configs"], index)
    return [r for r in results if r.control_id == control_id and r.status == Status.FAIL
            and r.assurance in DECISIVE_ASSURANCE]


def _candidate_target(stored: dict, req: RemediationCandidateRequest) -> int:
    """The config a candidate is for: an unconfirmed vendor with a decisive FAIL of this control."""
    if req.rule_id not in CONTROLS:
        raise HTTPException(404, f"Unknown control '{req.rule_id}'")
    index = _index(stored, req.device_hostname, req.config_index)
    if _confirmed(stored, index):
        raise HTTPException(409, "This device's vendor is confirmed: its remediation is generated and verified "
                                 "deterministically by POST /api/remediate, never proposed as a candidate.")
    if not _fails(stored, index, req.rule_id):
        raise HTTPException(409, f"Candidate remediation needs a confirmed failure of {req.rule_id}. This finding "
                                 "is not decided from validated evidence - confirm what the lines mean first.")
    return index


def _candidate_schema(stored: dict, item: cand.Candidate) -> RemediationCandidateSchema:
    """What the browser sees: the command, the simulated diff and every quoted line redacted."""
    index = item.config_index
    config = stored["configs"][index]
    identification = (stored.get("identifications") or [None] * (index + 1))[index]
    redactor = config_redactor([config])
    numbers, lines = zip(*item.evidence) if item.evidence else ((), ())
    return RemediationCandidateSchema(
        config_index=index,
        rule_id=item.control_id,
        title=CONTROLS[item.control_id].title,
        device_hostname=config.device.hostname,
        vendor=config.device.vendor.value,
        vendor_status=identification.status if identification is not None else "unknown",
        source=item.source,
        status=item.status.value,
        command=display_scrub(redactor, item.command),
        reason=display_scrub(redactor, item.reason),
        explanation=display_scrub(redactor, item.explanation),
        confidence=item.confidence,
        assumptions=[display_scrub(redactor, a) for a in item.assumptions],
        evidence=EvidenceSchema(line_numbers=list(numbers), lines=redact_lines(redactor, lines)),
        control_status_before=item.control_status_before,
        control_status_after=item.control_status_after,
        checks=_checks(item.checks),
        diff="\n".join(redact_lines(redactor, item.diff.split("\n"))) if item.diff else "",
        created_at=item.created_at,
        confirmed_at=item.confirmed_at,
    )


def _record(stored: dict, item: cand.Candidate) -> RemediationCandidateSchema:
    _candidates(stored)[item.key] = item
    return _candidate_schema(stored, item)


def _existing(stored: dict, req: RemediationCandidateRequest) -> cand.Candidate:
    index = _candidate_target(stored, req)
    item = _candidates(stored).get(f"{index}-{req.rule_id}")
    if item is None:
        raise HTTPException(404, f"No candidate remediation has been proposed for {req.rule_id} on this device")
    return item


@router.post("/remediation/candidate", response_model=RemediationCandidateSchema)
async def propose_candidate_manually(req: RemediationCandidateRequest):
    """Record the command an administrator proposes for a finding on an unconfirmed vendor (a draft)."""
    stored = _stored(req.scan_id)
    index = _candidate_target(stored, req)
    try:
        item = cand.new_candidate(stored["configs"][index].raw_config, index, req.rule_id,
                                  cand.SOURCE_MANUAL, req.command or "")
    except cand.CandidateError as e:
        raise HTTPException(422, str(e))
    return _record(stored, item)


@router.post("/remediation/candidate/generate", response_model=RemediationCandidateSchema)
async def generate_candidate(req: RemediationCandidateRequest):
    """Ask the AI for a candidate command. The answer is a draft like any other: unverified, unapplied."""
    stored = _stored(req.scan_id)
    index = _candidate_target(stored, req)
    if not is_available():
        raise HTTPException(503, "AI is not configured, so no candidate can be generated. "
                                 "Enter the command for this device yourself.")
    config = stored["configs"][index]
    fails = _fails(stored, index, req.rule_id)
    identification = (stored.get("identifications") or [None] * (index + 1))[index]
    proposal, detail = propose_candidate(
        CONTROLS[req.rule_id], config.raw_lines,
        sorted({n for r in fails for n in r.evidence.line_numbers}),
        recommendation=next((r.failure.recommendation for r in fails if r.failure), ""),
        vendor_status=identification.status if identification is not None else "unknown",
        detected_vendor=identification.detected_vendor.value if identification is not None else "unknown",
    )
    if proposal is None:
        raise HTTPException(503, f"No candidate could be generated for {req.rule_id} ({detail}). "
                                 "Enter the command for this device yourself.")
    try:
        item = cand.new_candidate(config.raw_config, index, req.rule_id, cand.SOURCE_AI, proposal.command,
                                  explanation=proposal.explanation, confidence=proposal.confidence,
                                  assumptions=proposal.assumptions)
    except cand.CandidateError as e:  # already validated in app.ai.remediation; refuse rather than repair
        raise HTTPException(503, f"The generated candidate was not usable: {e}")
    return _record(stored, item)


@router.post("/remediation/candidate/verify", response_model=RemediationCandidateSchema)
async def verify_candidate(req: RemediationCandidateRequest):
    """Simulate the candidate on a copy of the uploaded configuration and re-evaluate every control."""
    stored = _stored(req.scan_id)
    item = _existing(stored, req)
    if item.status == cand.CandidateStatus.CONFIRMED:
        raise HTTPException(409, "This candidate is already confirmed. Propose a new one to check a change.")
    original = stored["configs"][item.config_index].raw_config
    cand.verify(item, original)
    # the uploaded configuration is never edited: the simulation ran on a copy
    assert stored["configs"][item.config_index].raw_config == original
    return _candidate_schema(stored, item)


@router.post("/remediation/candidate/confirm", response_model=RemediationCandidateSchema)
async def confirm_candidate(req: RemediationCandidateRequest):
    """An administrator accepts the candidate. NetAuditAI still never applies it to a device."""
    stored = _stored(req.scan_id)
    item = _existing(stored, req)
    if item.status not in (cand.CandidateStatus.VERIFIED, cand.CandidateStatus.UNVERIFIED):
        raise HTTPException(409, f"A candidate in state '{item.status.value}' cannot be confirmed: "
                                 "check it against this configuration first.")
    cand.confirm(item)
    return _candidate_schema(stored, item)


@router.post("/remediation/candidate/reject", response_model=RemediationCandidateSchema)
async def reject_candidate(req: RemediationCandidateRequest):
    """Discard the candidate. Nothing about the scan, its posture or its findings changes."""
    stored = _stored(req.scan_id)
    item = _existing(stored, req)
    cand.reject(item, req.reason or "")
    return _candidate_schema(stored, item)


@router.post("/download-fixed")
async def download_fixed_configs(req: DownloadFixedRequest):
    """
    The configurations with every verified fix applied.

    Single config -> plain .cfg response; multiple -> .zip with one .cfg per fixed device.
    Unverified changes are never included.
    """
    stored = _stored(req.scan_id)
    inputs = _inputs(req.inputs)
    confirmed = [i for i in range(len(stored["configs"])) if _confirmed(stored, i)]
    if not confirmed:
        raise HTTPException(
            409,
            "Remediation needs a confirmed vendor profile. This configuration's vendor is unknown "
            "or unverified, so vendor commands cannot be generated, applied or verified.",
        )

    fixed = []
    for index in confirmed:
        plan = remediate_all(stored["configs"][index].raw_config, inputs, skip=set(_provisional(stored, index)))
        if plan.fixed_config is not None:
            fixed.append((plan.hostname or "device", plan.fixed_config))
    if not fixed:
        raise HTTPException(400, "No verified fixes are available for this scan (see the remediation plan)")

    if len(fixed) == 1:
        hostname, text = fixed[0]
        return Response(content=text, media_type="text/plain",
                        headers={"Content-Disposition": f'attachment; filename="{hostname}_fixed.cfg"'})

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        seen: dict[str, int] = {}
        for hostname, text in fixed:
            count = seen.get(hostname, 0)
            seen[hostname] = count + 1
            zf.writestr(f"{hostname}{f'_{count + 1}' if count else ''}_fixed.cfg", text)
    return Response(content=buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="NetAuditAI_Fixed_Configs.zip"'})
