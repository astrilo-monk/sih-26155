"""
The compliance report endpoint.

    stored scan → redacted scan response → remediation plan → PDF (one per device)

Nothing is evaluated here. The report is built from the same responses the browser gets, so what
it states and what the application shows can never disagree, and the redaction that protects the
API protects the report with it: every quoted configuration line arrives already scrubbed.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from app.api.routes.remediation import _device_plan, _inputs, _stored
from app.api.routes.scan import archived_scan, build_scan_response, get_scan_store
from app.api.schemas import DeviceRemediationPlanSchema
from app.db.scans import load_scan
from app.reporting.report import device_report_pdf
from app import ledger

router = APIRouter()


class ReportRequest(BaseModel):
    scan_id: str
    # One device's report; omitted means every device of the scan
    config_index: Optional[int] = None
    # The same values the remediation plan uses, so the report states the fixes the user would get
    inputs: dict[str, str] = {}
    # "executive": the one-page summary instead of the full technical report
    variant: Literal["full", "executive"] = "full"


def _filename(hostname: str) -> str:
    """A safe download name built from the hostname the configuration states."""
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", hostname or "device").strip("_") or "device"
    return f"{stem}_compliance_report.pdf"


@router.post("/report")
async def compliance_report(req: ReportRequest):
    """The compliance report as PDF. One device → a PDF; several → a .zip of one PDF per device.

    A scan restored from the archive after a restart is reported from its stored (redacted) response and the
    remediation plans made with default inputs when it was scanned."""
    if req.scan_id in get_scan_store():
        stored = _stored(req.scan_id)
        inputs = _inputs(req.inputs)
        scan = build_scan_response(req.scan_id)

        def plan_for(index):
            return _device_plan(stored, index, inputs)
    else:
        scan, plans = archived_scan(req.scan_id), (load_scan(req.scan_id) or (None, []))[1]
        if scan is None:
            raise HTTPException(404, "Scan not found")

        def plan_for(index):
            return DeviceRemediationPlanSchema(**plans[index])

    count = len(scan.devices)
    if req.config_index is not None and not 0 <= req.config_index < count:
        raise HTTPException(404, f"This scan has no configuration {req.config_index}")
    indexes = [req.config_index] if req.config_index is not None else list(range(count))

    reports = []
    for index in indexes:
        try:
            plan = plan_for(index)
        except Exception:
            # A report is worth having even when remediation cannot be planned; the section says so.
            plan = None
        pdf = device_report_pdf(scan, index, plan, ledger_entry=ledger.latest("scan", req.scan_id),
                                executive=req.variant == "executive")
        ledger.append("report", f"{req.scan_id}/{index}", pdf)
        reports.append((scan.devices[index].get("hostname"), pdf))

    if len(reports) == 1:
        hostname, pdf = reports[0]
        return Response(content=pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{_filename(hostname)}"'})

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        seen: dict[str, int] = {}
        for hostname, pdf in reports:
            name = _filename(hostname)
            count_for_name = seen.get(name, 0)
            seen[name] = count_for_name + 1
            archive.writestr(name if not count_for_name else name.replace(".pdf", f"_{count_for_name + 1}.pdf"), pdf)
    return Response(content=buffer.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="NetAuditAI_Compliance_Reports.zip"'})
