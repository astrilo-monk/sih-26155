# AI Layer Design

This document details how we integrate Google Gemini into our security auditor.

## AI vs. Deterministic Logic

To ensure the highest accuracy for the hackathon, we draw a hard line:
**AI is NOT used to detect vulnerabilities.** 

Detection is done by our deterministic python rules engine. We only use AI to *enrich* the results.

## How Gemini is Used

Once our rules engine generates a list of `Finding` objects, we pass that context to Gemini to accomplish three things:

1. **Plain-English Explanations:** The rules engine outputs technical jargon (e.g., "SNMPv2c active on GigabitEthernet0/1"). Gemini translates this to: "You are using an old version of SNMP which sends data in plain text, making it easy for hackers to sniff your network traffic."
2. **Scan Summaries:** Gemini summarizes the entire scan result for executives, highlighting the most critical issues.
3. **Chat Assistant:** An interactive chatbot where the user can ask questions like "Why is rule MGMT-001 failing?" or "Is there a workaround for this?"

## Remediation Generation: Deterministic Templates

To ensure the highest accuracy and safety for network gear, **we do not use AI to generate remediation commands.** 
Instead, we use deterministic, vendor-specific templates (e.g., in `remediation/engine.py`). While templates do not eliminate all security risks, they significantly reduce the risk of AI-hallucinated or malformed remediation commands on critical infrastructure, ensuring the fixes are much more reliable.

## Fallback Behavior

If the Gemini API is down, rate-limited, or we lose internet access during the demo, the application will fallback to displaying standard, pre-written descriptions for each rule ID, and basic static remediation templates. The detection and scoring will still work 100%.
