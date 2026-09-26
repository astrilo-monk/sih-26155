"""
Remediation API routes (Phase 8).

Every route works from a stored scan. For a **confirmed** vendor the deterministic
engine in ``app.remediation.engine`` does the work: a remediation runs only for a
decisive FAIL, is generated from a fixed recipe, and is reported FIXED only after a
full rescan verified it. No request field carries command text on that path.

For an **unconfirmed** vendor there is no recipe and no trusted grammar. Where a reviewed
recognizer read the failing line, seed write-back (``app.remediation.writeback``) rewrites that
line's value with the same recognizer and verifies it by a rescan: those fixes behave like a
confirmed vendor's, and ``/download-fixed`` includes them. For everything else,
``/remediation/candidate*`` offers the reviewed alternative: command text an
administrator typed or the AI proposed, validated and (where a deterministic effect
can be derived) simulated on a copy of the configuration, and confirmed by a human.
A candidate never becomes a fix, never changes the stored scan and is never executed.
A verified one can be downloaded as a corrected *copy* of the uploaded configuration,
from its own endpoint.
See ``app.remediation.candidates``.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.ai.client import is_available
from app.ai.redaction import Redactor
from app.ai.remediation import propose_candidate
from app.db.scans import load_scan
from app.api.routes.scan import (
    _device_results, config_redactor, display_scrub, get_scan_store, live_scan, redact_config_text, redact_lines,
)
from app.api.schemas import (
    ByHandSchema, DeviceRemediationPlanSchema, DownloadFixedRequest, EvidenceSchema, FinalDeviceSchema,
    FinalReviewResponse, PostureSummarySchema,
    RemediationCandidateRequest, RemediationCandidateSchema, RemediationCheckSchema, RemediationInputSchema,
    RemediationPlanRequest, RemediationPlanResponse, RemediationRequest, RemediationResponse,
)
from app.controls.catalog import CONTROLS
from app.models.normalized import Vendor
from app.models.results import DECISIVE_ASSURANCE, Status
from app.remediation import candidates as cand
from app.remediation.engine import (
    INPUTS, Outcome, RemediationStatus, analyze_generic_text, parse_inputs, remediate_all, remediate_control,
)
from app.remediation.writeback import writeback_all, writeback_control

router = APIRouter()


def _stored(scan_id: str) -> dict:
    stored = live_scan(scan_id)
    if not stored.get("configs"):
        raise HTTPException(400, "No configs available")
    return stored


def _inputs(raw: dict) -> dict:
    values, errors = parse_inputs(raw)
    if errors:
        raise HTTPException(422, {"message": "Invalid remediation inputs", "errors": errors})
    return values


def _device_inputs(req, index: int) -> dict:
    """The scan-wide values with this config's own values on top."""
    return _inputs({**req.inputs, **req.device_inputs.get(index, {})})


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
    elif outcome.status == RemediationStatus.VENDOR_UNVERIFIED:
        outcome = _written_back(stored, index, req.rule_id, inputs) or outcome
    return _response(outcome, index, _redactor(stored, inputs, index))


# What seed write-back settles for an unconfirmed vendor; anything else keeps the candidate path
_WRITTEN_BACK = (RemediationStatus.FIXED, RemediationStatus.NEEDS_INPUT, RemediationStatus.VERIFICATION_FAILED)


def _confirmed_commands(stored: dict, index: int) -> dict[str, str]:
    """Commands an administrator confirmed for this config that a reviewed recognizer reads line by line.

    Only these join the corrected configuration: a removal-verified candidate proves the finding is gone,
    not that the setting is secure, so it stays its own copy."""
    return {c.control_id: c.command for c in _candidates(stored).values()
            if c.config_index == index and c.status == cand.CandidateStatus.CONFIRMED and c.effect == "applied"}


def _written_back(stored: dict, index: int, control_id: str, inputs: dict) -> Optional[Outcome]:
    """Seed write-back for one control of an unconfirmed-vendor config, when it settles the control."""
    text = stored["configs"][index].raw_config
    command = _confirmed_commands(stored, index).get(control_id)
    outcome, after = writeback_control(text, control_id, inputs, command=command) if command else (None, None)
    if after is None:
        outcome, _ = writeback_control(text, control_id, inputs)
    if outcome.status not in _WRITTEN_BACK:
        return None
    config = stored["configs"][index]
    outcome.hostname, outcome.vendor = config.device.hostname, config.device.vendor.value
    return outcome


def _device_plan(stored: dict, index: int, inputs: dict) -> DeviceRemediationPlanSchema:
    config = stored["configs"][index]
    redactor = _redactor(stored, inputs, index)
    if not _confirmed(stored, index):
        results = _device_results(stored.get("result"), stored["configs"], index)
        flagged = [c for c in CONTROLS if any(r.control_id == c and (r.status == Status.FAIL or r.proposed_status)
                                              for r in results)]
        identification = (stored.get("identifications") or [None] * (index + 1))[index]
        # seed write-back settles what a reviewed recognizer can write; the rest keeps the candidate path
        plan = writeback_all(config.raw_config, inputs, commands=_confirmed_commands(stored, index))
        written = {o.control_id: o for o in plan.outcomes if o.status in _WRITTEN_BACK}
        for outcome in written.values():
            outcome.hostname, outcome.vendor = config.device.hostname, config.device.vendor.value
        return DeviceRemediationPlanSchema(
            config_index=index, device_hostname=config.device.hostname, vendor=config.device.vendor.value,
            vendor_status=identification.status if identification is not None else "unknown",
            remediations=[_response(written.get(c) or _gate(stored, index, c), index, redactor) for c in flagged],
            candidates=[_candidate_schema(stored, item) for item in _candidates(stored).values()
                        if item.config_index == index],
            fixed_controls=plan.fixed_controls, checks=_checks(plan.checks) if plan.fixed_controls else [],
            before=_summary(plan.before), after=_summary(plan.after) if plan.fixed_controls else None,
            fixed_config=redact_config_text(redactor, plan.fixed_config),
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
    """Remediate every failing control of every device; each change verified by a rescan.

    A scan restored from history answers with the plans archived when it was scanned (default inputs)."""
    if req.scan_id not in get_scan_store() and (archived := load_scan(req.scan_id)) is not None:
        return RemediationPlanResponse(
            scan_id=req.scan_id, inputs=[_input_schema(n) for n in INPUTS],
            devices=[DeviceRemediationPlanSchema(**p) for p in archived[1] if p is not None])
    stored = _stored(req.scan_id)
    return RemediationPlanResponse(
        scan_id=req.scan_id,
        inputs=[_input_schema(n) for n in INPUTS],
        devices=[_device_plan(stored, i, _device_inputs(req, i)) for i in range(len(stored["configs"]))],
    )


# -- candidate remediation (unconfirmed vendors) ------------------------------
# A candidate is command text from outside the engine (typed by an administrator, or proposed by the
# AI). It is validated, simulated on a copy where a deterministic effect can be derived, and confirmed
# by a human. It never changes the stored scan and is never executed. Once verified, the edited copy it
# was verified against can be downloaded from /remediation/candidate/download - a corrected copy of the
# uploaded file, never a device configuration and never part of /download-fixed.

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
        download_available=cand.downloadable(item),
        effect=item.effect,
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


@router.post("/remediation/candidate/derive", response_model=RemediationCandidateSchema)
async def derive_candidate(req: RemediationCandidateRequest):
    """NetAuditAI's own candidate, derived from the configuration and verified before it is offered.

    No vendor grammar and no AI: the change is the lines the decisive failure cites, removed from the
    block they sit in, checked by re-reading the edited copy. A control whose fix would be to *add* a
    setting has nothing to derive and says so; the uploaded configuration is never edited.
    """
    stored = _stored(req.scan_id)
    index = _candidate_target(stored, req)
    original = stored["configs"][index].raw_config
    item = cand.derive(original, index, req.rule_id)
    assert stored["configs"][index].raw_config == original
    if item is None:
        raise HTTPException(
            422,
            f"NetAuditAI cannot derive a change for {req.rule_id} from this configuration: it can only remove "
            "settings the finding cites, and this one needs a setting to be added or changed in syntax it does "
            "not know. Enter the command for this device yourself, or let AI propose one.",
        )
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


def _safe_name(*parts: str) -> str:
    """A filename built only from characters we choose: no path, no quotes, no header injection."""
    cleaned = [re.sub(r"[^A-Za-z0-9._-]+", "-", part).strip("-.") or "device" for part in parts]
    return "_".join(cleaned)[:120]


@router.post("/remediation/candidate/download")
async def download_candidate_config(req: RemediationCandidateRequest):
    """
    The verified corrected **copy** of the uploaded configuration for one candidate.

    This is not a device configuration NetAuditAI generated, and nothing has been applied anywhere: it
    is the uploaded text with the candidate's simulated change, exactly as it was re-analysed when the
    candidate verified. Only a VERIFIED candidate (or one confirmed after verifying) has that text at
    all - a draft, an unverified, a rejected or a re-checked-and-failed candidate has none, and is
    refused here. The stored scan, its configuration and its results are not touched.
    """
    stored = _stored(req.scan_id)
    item = _existing(stored, req)
    if not cand.downloadable(item):
        raise HTTPException(409, f"This candidate is '{item.status.value}': there is no verified corrected copy to "
                                 "download. A copy exists only after NetAuditAI verified the command against this "
                                 "configuration.")
    hostname = stored["configs"][item.config_index].device.hostname or "device"
    return Response(
        content=item.verified_config, media_type="text/plain",
        headers={
            "Content-Disposition":
                f'attachment; filename="{_safe_name(hostname, item.control_id)}_verified_copy.cfg"',
            # stated on the response itself, not written into the file: the file must stay byte-identical
            # to the text that was verified
            "X-NetAuditAI-Note": "Verified corrected copy of the uploaded configuration; not applied to any device",
        },
    )


def _final(stored: dict, index: int, inputs: dict):
    """The config with every verified fix and every simulated change you confirmed, and what is left by hand.

    Returns (fixed_text or None, before, after, included control ids, confirmed commands with no simulated
    effect). A removal you confirmed drops the lines it was verified against; a command NetAuditAI could not
    simulate is never written into the file."""
    text = stored["configs"][index].raw_config
    if _confirmed(stored, index):
        plan = remediate_all(text, inputs, skip=set(_provisional(stored, index)))
        return plan.fixed_config, plan.before, plan.after, list(plan.fixed_controls), []
    confirmed = [c for c in _candidates(stored).values()
                 if c.config_index == index and c.status == cand.CandidateStatus.CONFIRMED]
    removals = [c for c in confirmed if c.effect == "removal"]
    copy = cand.apply_to_copy(text, {n for c in removals for n, _ in c.evidence}) if removals else text
    plan = writeback_all(copy, inputs, commands=_confirmed_commands(stored, index))
    final = plan.fixed_config or copy
    included = list(dict.fromkeys([*plan.fixed_controls, *(c.control_id for c in removals)]))
    by_hand = [c for c in confirmed if c.effect not in ("applied", "removal")]
    before = analyze_generic_text(text).summary()
    after = analyze_generic_text(final).summary() if final != text else before
    return (final if final != text else None), before, after, included, by_hand


@router.post("/remediation/final", response_model=FinalReviewResponse)
async def remediation_final(req: RemediationPlanRequest):
    """The score once everything you decided is in: verified fixes plus the candidates you confirmed."""
    stored = _stored(req.scan_id)
    devices = []
    for index, config in enumerate(stored["configs"]):
        fixed, before, after, included, by_hand = _final(stored, index, _device_inputs(req, index))
        redactor = config_redactor([config])
        devices.append(FinalDeviceSchema(
            config_index=index, device_hostname=config.device.hostname,
            before=_summary(before), after=_summary(after), included=included, changed=fixed is not None,
            by_hand=[ByHandSchema(control_id=c.control_id, command=display_scrub(redactor, c.command)) for c in by_hand],
        ))
    return FinalReviewResponse(scan_id=req.scan_id, devices=devices)


@router.post("/download-fixed")
async def download_fixed_configs(req: DownloadFixedRequest):
    """
    The configurations with every verified fix applied.

    Single config -> plain .cfg response; multiple -> .zip with one .cfg per fixed device.
    Unverified changes are never included.
    """
    stored = _stored(req.scan_id)

    fixed = []
    for index, config in enumerate(stored["configs"]):
        inputs = _device_inputs(req, index)
        if req.include_confirmed:
            text = _final(stored, index, inputs)[0]
            if text is not None:
                fixed.append((config.device.hostname or "device", text))
            continue
        if _confirmed(stored, index):
            plan = remediate_all(config.raw_config, inputs, skip=set(_provisional(stored, index)))
        else:
            # only what a reviewed recognizer wrote and the rescan verified
            plan = writeback_all(config.raw_config, inputs, commands=_confirmed_commands(stored, index))
        if plan.fixed_config is not None:
            fixed.append((config.device.hostname or plan.hostname or "device", plan.fixed_config))
    if not fixed and not any(_confirmed(stored, i) for i in range(len(stored["configs"]))):
        raise HTTPException(
            409,
            "This configuration's vendor is unknown or unverified, and no reviewed recognizer could write a "
            "verified fix for it. Propose a command for each finding instead.",
        )
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
