"""
AI assistant route.

Provides a chat interface where users can ask questions about
their scan results. Also has an endpoint to get AI explanations
for individual findings.
"""

from __future__ import annotations
from fastapi import APIRouter, HTTPException
from app.api.schemas import AssistantRequest, AssistantResponse
from app.api.routes.scan import get_scan_store
from app.ai.client import generate, is_available
from app.ai.prompts import explain_finding, generate_summary

router = APIRouter()


CHAT_SYSTEM_PROMPT = """You are NetAuditAI, a network security compliance assistant.
You help network engineers understand security findings from configuration audits.
You have access to the user's scan results. Be helpful, specific, and practical.
When referencing findings, use their rule IDs. Keep answers concise.
If asked about something outside your scope, say so politely."""


@router.post("/assistant/chat", response_model=AssistantResponse)
async def chat(req: AssistantRequest):
    """Chat with the AI assistant about scan results."""
    if not is_available():
        return AssistantResponse(
            response="AI features are not configured. Set GEMINI_API_KEY in your .env file.",
            scan_id=req.scan_id,
        )

    store = get_scan_store()
    stored = store.get(req.scan_id)

    context = ""
    if stored:
        result = stored["result"]
        findings_summary = "\n".join(
            f"- [{f.severity.value.upper()}] {f.rule_id}: {f.title} (on {f.device_hostname})"
            for f in result.findings
        )
        context = f"""
Current scan context:
- Score: {result.score}/100
- Total findings: {result.total_findings}
- Critical: {result.critical_count}, High: {result.high_count}, Medium: {result.medium_count}, Low: {result.low_count}
- Devices: {', '.join(d.get('hostname', 'unknown') for d in result.devices)}

Findings:
{findings_summary}
"""

    prompt = f"{context}\n\nUser question: {req.message}"
    response = generate(prompt, CHAT_SYSTEM_PROMPT)

    if response is None:
        response = "Sorry, I couldn't generate a response. Please try again."

    return AssistantResponse(response=response, scan_id=req.scan_id)


@router.get("/assistant/explain/{scan_id}/{rule_id}/{hostname}")
async def explain(scan_id: str, rule_id: str, hostname: str):
    """Get an AI explanation for a specific finding."""
    store = get_scan_store()
    stored = store.get(scan_id)
    if not stored:
        raise HTTPException(404, "Scan not found")

    result = stored["result"]
    finding = None
    for f in result.findings:
        if f.rule_id == rule_id and f.device_hostname == hostname:
            finding = f
            break

    if not finding:
        raise HTTPException(404, "Finding not found")

    if not is_available():
        return {
            "rule_id": rule_id,
            "explanation": finding.recommendation,
            "ai_generated": False,
        }

    explanation = explain_finding(finding)
    return {
        "rule_id": rule_id,
        "explanation": explanation or finding.recommendation,
        "ai_generated": explanation is not None,
    }


@router.get("/assistant/summary/{scan_id}")
async def summary(scan_id: str):
    """Get an AI-generated summary of scan results."""
    store = get_scan_store()
    stored = store.get(scan_id)
    if not stored:
        raise HTTPException(404, "Scan not found")

    result = stored["result"]

    if not is_available():
        return {
            "summary": f"Scan found {result.total_findings} security issues "
                       f"({result.critical_count} critical). Score: {result.score}/100.",
            "ai_generated": False,
        }

    hostname = result.devices[0].get("hostname", "unknown") if result.devices else "unknown"
    vendor = result.devices[0].get("vendor", "unknown") if result.devices else "unknown"
    top_findings = [f"{f.severity.value.upper()}: {f.title}" for f in result.findings[:10]]

    text = generate_summary(
        hostname, vendor, result.score,
        result.critical_count, result.high_count,
        result.medium_count, result.low_count,
        top_findings,
    )

    return {
        "summary": text or f"Scan found {result.total_findings} issues. Score: {result.score}/100.",
        "ai_generated": text is not None,
    }


@router.get("/assistant/status")
async def ai_status():
    """Check if AI features are available."""
    return {"ai_available": is_available()}
