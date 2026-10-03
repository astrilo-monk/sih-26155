import secrets
import time

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from app.api.routes import scan, remediation, assistant, adaptive, report, collect, ledger
from app import config as app_config
from app.config import settings
from app.db.database import DB_TIME

app = FastAPI(
    title="NetAuditAI",
    description="AI-driven multi-vendor network security compliance auditor",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Server-Timing"],
)


@app.middleware("http")
async def server_timing(request: Request, call_next):
    """Server-Timing on every response: time in Postgres, in SQLite, and in total. The browser's DevTools show it,
    so a slow request on the host can be told apart from a slow network without access to the host."""
    spent: dict = {}
    DB_TIME.set(spent)
    start = time.perf_counter()
    response = await call_next(request)
    parts = [f"{engine};dur={seconds * 1000:.0f}" for engine, seconds in spent.items()]
    response.headers["Server-Timing"] = ", ".join([*parts, f"total;dur={(time.perf_counter() - start) * 1000:.0f}"])
    response.headers["Timing-Allow-Origin"] = "*"
    return response


def require_api_key(key: str | None = Security(APIKeyHeader(name="X-API-Key", auto_error=False))):
    """Open when API_KEY is unset; otherwise the header must match it.

    The key is read at call time, not bound at import: a config reload replaces the settings object,
    and a stale reference here would keep authorising against the key the process started with.
    """
    configured = app_config.settings.api_key
    if configured and not secrets.compare_digest((key or "").encode(), configured.encode()):
        raise HTTPException(401, "Missing or invalid API key")


api = [Depends(require_api_key)]
app.include_router(scan.router, prefix="/api", tags=["scan"], dependencies=api)
app.include_router(remediation.router, prefix="/api", tags=["remediation"], dependencies=api)
app.include_router(assistant.router, prefix="/api", tags=["assistant"], dependencies=api)
app.include_router(adaptive.router, prefix="/api", tags=["adaptive"], dependencies=api)
app.include_router(report.router, prefix="/api", tags=["report"], dependencies=api)
app.include_router(collect.router, prefix="/api", tags=["collect"], dependencies=api)
app.include_router(ledger.router, prefix="/api", tags=["ledger"], dependencies=api)


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "NetAuditAI"}
