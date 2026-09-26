"""The audit ledger over HTTP: read it, verify the whole chain, and check a report PDF (or the .zip of a scan's
reports) against it."""

from __future__ import annotations

import io
import zipfile
import zlib

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


def _reports(content: bytes) -> list[tuple[str, bytes]]:
    """The PDFs to check: the file itself, or every member of the .zip a multi-device scan downloads as."""
    if not zipfile.is_zipfile(io.BytesIO(content)):
        return [("", content)]
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = [m for m in archive.infolist() if not m.is_dir()]
        # declared sizes are checked before anything is inflated: no zip bomb
        if not members or len(members) > 100 or sum(m.file_size for m in members) > MAX_REPORT_BYTES:
            raise HTTPException(413, "That archive is not one NetAuditAI generates")
        try:
            return [(m.filename, archive.read(m)) for m in members]
        except (zipfile.BadZipFile, EOFError, zlib.error):  # damaged (e.g. edited): checked as one file, so it matches nothing
            return [("", content)]


@router.post("/verify-report")
async def verify_report(file: UploadFile = File(...)):
    """Is this PDF, byte for byte, a report NetAuditAI generated? A .zip matches when every PDF in it does. Only
    hashes are compared; nothing is kept."""
    content = await file.read(MAX_REPORT_BYTES + 1)
    if len(content) > MAX_REPORT_BYTES:
        raise HTTPException(413, "That file is larger than any report NetAuditAI generates")
    files = [{"name": name, "sha256": ledger.digest(data), "entry": ledger.find(ledger.digest(data), kind="report")}
             for name, data in _reports(content)]
    return {"match": all(f["entry"] for f in files), "sha256": ledger.digest(content), "entry": files[0]["entry"],
            "files": files, "chain": ledger.verify()}
