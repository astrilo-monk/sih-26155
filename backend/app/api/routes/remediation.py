"""
Remediation API routes (Phase 8).

Every route works from a stored scan and the deterministic engine in
``app.remediation.engine``: a remediation runs only for a decisive FAIL on a
confirmed vendor, and is reported FIXED only after a full rescan verified it.
No request field carries command text.
"""

from __future__ import annotations

import io
import zipfile
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.ai.redaction import Redactor
from app.api.routes.scan import (
    _device_results, config_redactor, display_scrub, get_scan_store, redact_config_text, redact_lines,
)
from app.api.schemas import (
    DeviceRemediationPlanSchema, DownloadFixedRequest, EvidenceSchema, PostureSummarySchema,
    RemediationCheckSchema, RemediationInputSchema, RemediationPlanRequest, RemediationPlanResponse,
    RemediationRequest, RemediationResponse,
)
from app.controls.catalog import CONTROLS
from app.models.normalized import Vendor
from app.models.results import DECISIVE_ASSURANCE, Status
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
    configs = stored["configs"]
    if req.config_index is not None:
        if not 0 <= req.config_index < len(configs) or configs[req.config_index].device.hostname != req.device_hostname:
            raise HTTPException(404, "Device not found in scan")
        index = req.config_index
    else:
        # A hostname is display metadata: it identifies a config only when no other upload shares it
        matches = [i for i, c in enumerate(configs) if c.device.hostname == req.device_hostname]
        if not matches:
            raise HTTPException(404, "Device not found in scan")
        if len(matches) > 1:
            raise HTTPException(409, f"{len(matches)} configs in this scan are named '{req.device_hostname}': "
                                     "pass config_index to choose one")
        index = matches[0]
    inputs = _inputs(req.inputs)

    outcome = _gate(stored, index, req.rule_id)
    if outcome is None:
        outcome, _ = remediate_control(configs[index].raw_config, req.rule_id, inputs)
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
