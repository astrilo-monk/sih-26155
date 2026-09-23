"""
AI assistant route.

Provides a chat interface where users can ask questions about
their scan results. Also has an endpoint to get AI explanations
for individual findings.
"""

from __future__ import annotations
from fastapi import APIRouter, HTTPException
from app.api.schemas import AssistantRequest, AssistantResponse
from app.api.routes.scan import config_redactor as _config_redactor, get_scan_store, get_scan_result_or_409
from app.ai.client import generate, is_available
from app.ai.prompts import explain_finding, generate_summary

router = APIRouter()


def _score_text(score) -> str:
    return f"{score}/100" if score is not None else "not assessed"


CHAT_SYSTEM_PROMPT = """You are NetAuditAI, a network security compliance assistant.
You help network engineers understand the results of a configuration audit.

You are given the audit's own conclusions. Treat them as the facts. Never contradict a verdict, and
never invent a setting, serial, version or line the context does not contain. If the context does not
answer the question, say what is missing and what would settle it -that is a useful answer here.

Two distinctions the engine makes, which you must keep:
  * A check is decided (pass/fail) only from decisive evidence. "Not configured" and "unknown" are
    NOT failures: they mean the setting was absent or could not be read, and the engine refuses to
    guess. Explain them that way rather than implying the device failed.
  * A provisional verdict (heuristic, ai_verified) is a suspicion awaiting confirmation. Say so when
    one comes up; it does not move the posture score.

Cite checks by their control id and findings by their rule id. Be concise and practical."""

# A conversation is context, not storage: only the recent turns are sent, and each is capped
MAX_HISTORY_TURNS = 8
MAX_TURN_CHARS = 600


def _scan_context(scan_id: str) -> str:
    """What the assistant is allowed to know, taken from the response the browser already has.

    Built from ``build_scan_response`` rather than the raw result on purpose: that response is the
    redacted view, so every configuration quote in it has already had its secrets removed. The
    assistant therefore cannot be handed a password by a path that forgot to scrub one.
    """
    from app.api.routes.scan import build_scan_response  # assistant is imported from scan's module

    scan = build_scan_response(scan_id)
    devices = ", ".join(
        f"{d.get('hostname', 'unknown')} ({d.get('vendor', 'unknown')})" for d in scan.devices
    ) or "none"

    lines = [
        "AUDIT RESULT",
        f"Devices: {devices}",
        f"Posture: {scan.posture if scan.posture is not None else 'not assessed'}"
        f"  Coverage: {scan.coverage if scan.coverage is not None else 'n/a'}%"
        f"  (posture scores the checks that were decided; coverage is how many could be)",
        f"Findings: {scan.total_findings} -{scan.critical} critical, {scan.high} high, "
        f"{scan.medium} medium, {scan.low} low",
    ]
    if scan.framework:
        lines.append(f"Reported against: {scan.framework}")

    if scan.findings:
        lines.append("\nFINDINGS")
        lines += [f"- [{f.severity.upper()}] {f.rule_id}: {f.title} (on {f.device_hostname})"
                  for f in scan.findings]

    if scan.results:
        lines.append("\nEVERY CHECK, INCLUDING THE ONES NOT DECIDED")
        for r in scan.results:
            assurance = f", {r.assurance}" if r.assurance else ""
            lines.append(f"- {r.control_id} [{r.status}{assurance}] {r.title}: {r.reason}")
    return "\n".join(lines)


def _history_text(history) -> str:
    recent = [t for t in history if t.content.strip()][-MAX_HISTORY_TURNS:]
    if not recent:
        return ""
    turns = "\n".join(f"{'Operator' if t.role != 'assistant' else 'You'}: "
                      f"{t.content.strip()[:MAX_TURN_CHARS]}" for t in recent)
    return f"\nEARLIER IN THIS CONVERSATION\n{turns}\n"


@router.post("/assistant/chat", response_model=AssistantResponse)
async def chat(req: AssistantRequest):
    """Chat with the AI assistant about scan results."""
    if not is_available():
        return AssistantResponse(
            response="AI features are not configured. Set GROQ_API_KEY in your .env file.",
            scan_id=req.scan_id,
        )

    store = get_scan_store()
    stored = store.get(req.scan_id)

    if stored is None:
        return AssistantResponse(
            response="This backend no longer holds that scan, so I cannot see its results. Scans are "
                     "kept in memory and cleared on restart -upload the configuration again to ask "
                     "about it.",
            scan_id=req.scan_id,
        )

    context = _scan_context(req.scan_id) if stored.get("result") is not None else (
        "AUDIT RESULT\nThis scan produced no compliance result yet, so there is nothing to report on.")

    # The question and the conversation may quote secrets: redact keyword forms (as prose) and any
    # secret value known from the scanned configs. The context is already redacted by construction.
    redactor = _config_redactor(stored.get("configs"))
    scrub = lambda text: redactor.scrub(redactor.text(text, prose=True))
    question = scrub(req.message)
    prompt = f"{context}\n{scrub(_history_text(req.history))}\nOperator's question: {question}"
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

    result = get_scan_result_or_409(stored)
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

    explanation = explain_finding(finding, _config_redactor(stored.get("configs")))
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

    result = get_scan_result_or_409(stored)

    if not is_available():
        return {
            "summary": f"Scan found {result.total_findings} security issues "
                       f"({result.critical_count} critical). Score: {_score_text(result.score)}.",
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
        "summary": text or f"Scan found {result.total_findings} issues. Score: {_score_text(result.score)}.",
        "ai_generated": text is not None,
    }


@router.get("/assistant/status")
async def ai_status():
    """Check if AI features are available."""
    return {"ai_available": is_available()}
