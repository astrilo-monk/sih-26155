import secrets

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from app.api.routes import scan, remediation, assistant, adaptive, report, collect
from app.config import settings

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
    expose_headers=["Content-Disposition"],
)


def require_api_key(key: str | None = Security(APIKeyHeader(name="X-API-Key", auto_error=False))):
    """Open when API_KEY is unset; otherwise the header must match it."""
    if settings.api_key and not secrets.compare_digest((key or "").encode(), settings.api_key.encode()):
        raise HTTPException(401, "Missing or invalid API key")


api = [Depends(require_api_key)]
app.include_router(scan.router, prefix="/api", tags=["scan"], dependencies=api)
app.include_router(remediation.router, prefix="/api", tags=["remediation"], dependencies=api)
app.include_router(assistant.router, prefix="/api", tags=["assistant"], dependencies=api)
app.include_router(adaptive.router, prefix="/api", tags=["adaptive"], dependencies=api)
app.include_router(report.router, prefix="/api", tags=["report"], dependencies=api)
app.include_router(collect.router, prefix="/api", tags=["collect"], dependencies=api)


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "NetAuditAI"}
