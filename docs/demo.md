# Demo Flow

This is the 10-step script we will use when presenting to the SIH judges. We need to make sure the app can flawlessly execute these steps.

## The Script

1. **Introduction:** Briefly explain the problem (multi-vendor networks are a nightmare to audit manually).
2. **The Dashboard:** Show the clean React dashboard (currently empty).
3. **Upload Cisco:** Upload a purposely vulnerable Cisco IOS config (e.g., Telnet enabled, weak passwords).
4. **Auto-Detection:** Show the UI correctly identifying it as Cisco IOS without user input.
5. **The Results (Cisco):** Reveal the generated report. Show the low score (e.g., 45/100) and the list of findings.
6. **AI Explanation:** Click on a critical finding (like MGMT-001 Telnet). Show Gemini explaining *why* it's bad in plain English.
7. **Reliable Remediation:** Click "Fix this". Emphasize that while we use AI for explanations, we deliberately use **deterministic templates** for remediation. Explain that while this doesn't eliminate all security risks, it significantly reduces the risk of generating hallucinated or malformed commands on critical infrastructure. Show the generated Cisco CLI commands to disable Telnet and enable SSH.
8. **Upload FortiGate:** Upload a FortiGate config with different vulnerabilities (e.g., any-any firewall rule).
9. **The Results (FortiGate):** Show the UI parsing the FortiGate config flawlessly and applying the *exact same* rules engine to generate a score.
10. **Conclusion:** Explain our architecture (the Normalized Model) and why it makes our tool infinitely scalable to new vendors.

*(Note: We need to build specific text fixtures for Step 3 and Step 8 to ensure the demo is predictable.)*
