# Project Requirements (SIH26155)

This document tracks what we actually need to build for the hackathon to satisfy the problem statement.

## MVP Requirements (Must Have for Demo)
- [x] Basic project structure and models
- [x] Vendor detection logic
- [ ] Parse at least 2 distinct vendor configs (Targeting Cisco IOS and FortiGate)
- [ ] Normalize configurations into a standard format
- [ ] Deterministic rules engine (Implement ~15 key security rules)
- [ ] Compliance mapping (Basic mapping to CIS/NIST)
- [ ] Security scoring system
- [ ] AI Integration (Gemini) for plain-English explanations of risks
- [ ] AI-generated remediation snippets (e.g., the exact CLI commands to fix a finding)
- [ ] Basic React dashboard to upload configs and view results

## Stretch Goals (If we have time)
- [ ] Interactive AI Assistant (chat with your config)
- [ ] Support for a 3rd vendor (maybe Palo Alto or Juniper?)
- [ ] PDF Report Generation
- [ ] Historical scan comparisons

*Note: Keep it simple. Let's make sure the MVP is rock solid before trying to build a chatbot.*
