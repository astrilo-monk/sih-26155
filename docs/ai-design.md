# AI Layer Design

This document details how we integrate Google Gemini into our security auditor.

## AI vs. Deterministic Logic

To ensure the highest accuracy for the hackathon, we draw a hard line:
**AI is NOT used to detect vulnerabilities.** 

Detection is done by our deterministic python rules engine. We only use AI to *enrich* the results.

## How Gemini is Used

Once our rules engine generates a list of `Finding` objects, we pass that context to Gemini to accomplish three things:

1. **Plain-English Explanations:** The rules engine outputs technical jargon (e.g., "SNMPv2c active on GigabitEthernet0/1"). Gemini translates this to: "You are using an old version of SNMP which sends data in plain text, making it easy for hackers to sniff your network traffic."
2. **Remediation Generation:** Gemini generates the *exact* CLI commands needed to fix the issue based on the specific vendor and version. 
3. **Chat Assistant (Planned):** An interactive chatbot where the user can ask questions like "Why is rule SEC-003 failing?" or "Is there a workaround for this?"

## Hallucination Mitigation

Since LLMs can hallucinate commands (which is disastrous on network gear), we implement these safeguards:
* We provide strict system prompts dictating the expected output format.
* We pass the *exact* vendor and OS version detected in the config to ground the context.
* We include a UI disclaimer that all AI-generated CLI commands must be reviewed before execution.

## Fallback Behavior

If the Gemini API is down, rate-limited, or we lose internet access during the demo, the application will fallback to displaying standard, pre-written descriptions for each rule ID, and basic static remediation templates. The detection and scoring will still work 100%.
