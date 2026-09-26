"""The audit ledger over HTTP: read it, verify the whole chain, and check a report PDF against it."""

from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile

from app import ledger

router = APIRouter(prefix="/ledger")

MAX_REPORT_BYTES = 20 * 1024 * 1024


@router.get("")
async def list_entries(limit: int = 100):
    """The most recent entries, newest first."""
    return {"entries": ledger.entries(max(1, min(limit, 500)))}


@router.get("/verify")
async def verify_chain():
    """Recompute every hash: ``ok`` False names the first entry that no longer checks out."""
    return ledger.verify()


@router.post("/verify-report")
async def verify_report(file: UploadFile = File(...)):
    """Is this PDF, byte for byte, a report NetAuditAI generated? Only its hash is compared; nothing is kept."""
    content = await file.read(MAX_REPORT_BYTES + 1)
    if len(content) > MAX_REPORT_BYTES:
        raise HTTPException(413, "That file is larger than any report NetAuditAI generates")
    entry = ledger.find(ledger.digest(content), kind="report")
    return {"match": entry is not None, "sha256": ledger.digest(content), "entry": entry,
            "chain": ledger.verify()}
