from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import scan, remediation, assistant

app = FastAPI(
    title="NetAuditAI",
    description="AI-driven multi-vendor network security compliance auditor",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router, prefix="/api", tags=["scan"])
app.include_router(remediation.router, prefix="/api", tags=["remediation"])
app.include_router(assistant.router, prefix="/api", tags=["assistant"])


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "NetAuditAI"}

