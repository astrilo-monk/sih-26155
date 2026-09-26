"""
AI explanation prompts.

Takes a security finding and generates a human-readable
explanation using Groq.
"""

from __future__ import annotations
from typing import Optional
from app.models.findings import Finding
from app.ai.client import generate
from app.ai.redaction import Redactor
from app.ai.fence import DATA_RULE, fence


EXPLAIN_SYSTEM_PROMPT = """You are a network security expert explaining a vulnerability 
found in a network device configuration. Your audience is a network engineer or IT admin 
who needs to understand:
1. What the vulnerability is, in plain terms
2. How an attacker could exploit it
3. Real-world risk
4. The specific fix steps

Keep your response under 200 words. Be direct and practical, not academic.
Use bullet points for fix steps. Reference the specific config lines shown.
"""
EXPLAIN_SYSTEM_PROMPT += DATA_RULE


def explain_finding(finding: Finding, redactor: Optional[Redactor] = None) -> str | None:
    """Generate an AI explanation for a finding. Returns None if AI is unavailable.

    Evidence lines are redacted, and every secret value seen in them (or
    registered on ``redactor``) is scrubbed from the surrounding text.
    """
    redactor = redactor or Redactor()
    evidence_lines = [redactor.line(line) for line in finding.evidence_lines]
    scrub = redactor.scrub
    evidence = fence([scrub(line) for line in evidence_lines]) if evidence_lines else "(no evidence lines)"

    prompt = f"""Explain this network security finding:

**Rule:** {finding.rule_id} - {scrub(finding.title)}
**Severity:** {finding.severity.value}
**Device:** {finding.device_hostname} ({finding.vendor})
**Description:** {scrub(finding.description)}

**Config Evidence:**
```
{evidence}
```

**Recommendation:** {scrub(finding.recommendation)}

Explain this in plain terms for a network engineer. What's the risk and how to fix it?"""

    return generate(prompt, EXPLAIN_SYSTEM_PROMPT)


SUMMARY_SYSTEM_PROMPT = """You are a network security auditor writing a brief executive 
summary of a security scan. Be direct, professional, and actionable. 
Keep it under 150 words. Focus on the most critical issues first."""


def generate_summary(
    hostname: str,
    vendor: str,
    score: Optional[int],
    critical: int,
    high: int,
    medium: int,
    low: int,
    top_findings: list[str],
) -> str | None:
    """Generate an AI summary of scan results."""
    findings_text = "\n".join(f"- {f}" for f in top_findings[:10])
    score_text = f"{score}/100" if score is not None else "not assessed (no check could evaluate evidence)"

    prompt = f"""Write a brief security posture summary for:

**Device:** {hostname} ({vendor})
**Security Score:** {score_text}
**Findings:** {critical} critical, {high} high, {medium} medium, {low} low

**Top Issues:**
{findings_text}

Write 2-3 sentences summarizing the security posture and the most urgent actions needed."""

    return generate(prompt, SUMMARY_SYSTEM_PROMPT)
