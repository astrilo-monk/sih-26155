# Demo Flow

This is the 11-step script we will use when presenting to the SIH judges. We need to make sure the app can flawlessly execute these steps.

## The Script

1. **Introduction:** Briefly explain the problem (multi-vendor networks are a nightmare to audit manually).
2. **The Dashboard:** Show the React dashboard and the upload screen.
3. **Upload Cisco:** Upload a purposely vulnerable Cisco IOS config (e.g., Telnet enabled, weak passwords).
4. **Auto-Detection:** Explain that the backend detects Cisco IOS from configuration patterns and selects the parser automatically.
5. **The Results (Cisco):** Reveal the generated report. Show the low score (e.g., 45/100) and the list of findings.
6. **Finding Explanation:** Open a critical finding such as MGMT-001 Telnet and show its description, security impact, evidence, recommendation, and compliance mappings. If a Groq key is configured, the assistant API can provide an AI explanation.
7. **Reliable Remediation:** Click "Fix this". Emphasize that while we use AI for explanations, we deliberately use **deterministic templates** for remediation. Explain that while this doesn't eliminate all security risks, it significantly reduces the risk of generating hallucinated or malformed commands on critical infrastructure. Show the generated Cisco CLI commands to disable Telnet and enable SSH.
8. **Upload FortiGate:** Upload a FortiGate config with different vulnerabilities (e.g., any-any firewall rule).
9. **The Results (FortiGate):** Show the UI parsing the FortiGate config flawlessly and applying the *exact same* rules engine to generate a score.
10. **Unknown Vendor (optional):** Upload `sample/unknown.cfg` or `sample/paloalto.cfg`. Show that:
    * the vendor stays `unknown`, with vendor evidence shown separately
    * the score is marked provisional
    * uncertain lines appear in the **Training** tab

    Accept one mapping, then rescan: the learned mapping is applied with no AI call. Before the demo, check the Groq quota. If it is used up, lines show "AI unavailable" and must be mapped manually.
11. **Conclusion:** Explain our architecture (the Normalized Model plus the adaptive layer) and why it gives us a practical path to new vendors. Do not claim that every vendor or syntax variation is already supported.

*(Note: Use `backend/tests/fixtures/cisco_vulnerable.cfg` and `backend/tests/fixtures/fortinet_vulnerable.cfg` for a predictable demo.)*
