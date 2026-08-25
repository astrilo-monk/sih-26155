"""
AI explanation prompts.

Takes a security finding and generates a human-readable
explanation using Gemini.
"""

from __future__ import annotations
from app.models.findings import Finding
from app.ai.client import generate


EXPLAIN_SYSTEM_PROMPT = """You are a network security expert explaining a vulnerability 
found in a network device configuration. Your audience is a network engineer or IT admin 
who needs to understand:
1. What the vulnerability is, in plain terms
2. How an attacker could exploit it
3. Real-world risk
4. The specific fix steps

Keep your response under 200 words. Be direct and practical, not academic.
Use bullet points for fix steps. Reference the specific config lines shown."""


def explain_finding(finding: Finding) -> str | None:
    """Generate an AI explanation for a finding. Returns None if AI is unavailable."""
    evidence = "\n".join(finding.evidence_lines) if finding.evidence_lines else "(no evidence lines)"

    prompt = f"""Explain this network security finding:

**Rule:** {finding.rule_id} - {finding.title}
**Severity:** {finding.severity.value}
**Device:** {finding.device_hostname} ({finding.vendor})
**Description:** {finding.description}

**Config Evidence:**
```
{evidence}
```

**Recommendation:** {finding.recommendation}

Explain this in plain terms for a network engineer. What's the risk and how to fix it?"""

    return generate(prompt, EXPLAIN_SYSTEM_PROMPT)


SUMMARY_SYSTEM_PROMPT = """You are a network security auditor writing a brief executive 
summary of a security scan. Be direct, professional, and actionable. 
Keep it under 150 words. Focus on the most critical issues first."""


def generate_summary(
    hostname: str,
    vendor: str,
    score: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    top_findings: list[str],
) -> str | None:
    """Generate an AI summary of scan results."""
    findings_text = "\n".join(f"- {f}" for f in top_findings[:10])

    prompt = f"""Write a brief security posture summary for:

**Device:** {hostname} ({vendor})
**Security Score:** {score}/100
**Findings:** {critical} critical, {high} high, {medium} medium, {low} low

**Top Issues:**
{findings_text}

Write 2-3 sentences summarizing the security posture and the most urgent actions needed."""

    return generate(prompt, SUMMARY_SYSTEM_PROMPT)
