# Project Requirements (SIH26155)

This document tracks what we actually need to build for the hackathon to satisfy the problem statement.

## MVP Requirements (Must Have for Demo)
- [x] Basic project structure and models
- [x] Vendor detection logic
- [x] Parse at least 2 distinct vendor configs (Cisco IOS and FortiGate)
- [x] Normalize configurations into a standard format
- [x] Deterministic rules engine with 15 security rules
- [x] Compliance mapping to CIS and NIST 800-53
- [x] Security scoring system
- [x] Optional Gemini integration for explanations, summaries, and chat
- [x] Deterministic vendor-specific remediation snippets
- [x] React dashboard to upload configs and view results

## Stretch Goals (If we have time)
- [x] Backend AI assistant endpoints (frontend chat UI still pending)
- [ ] Support for a 3rd vendor (maybe Palo Alto or Juniper?)
- [ ] PDF Report Generation
- [ ] Historical scan comparisons

*Note: The MVP flow works locally. The next priority is improving persistence, parser coverage, remediation verification, and test coverage before treating this as a production tool.*
