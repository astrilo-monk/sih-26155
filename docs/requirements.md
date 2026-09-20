# Project Requirements (SIH26155)

What the hackathon build needs, and where it stands.

## Must have
- [x] Upload configurations and detect the vendor deterministically
- [x] Dedicated parsers for two distinct vendors (Cisco IOS, FortiGate)
- [x] Vendor-agnostic analysis for other vendors (generic tokenizer, heuristics, recognizers) — honestly provisional
- [x] Deterministic security controls with evidence (15 controls)
- [x] Compliance mappings to NIST SP 800-53 Rev. 5, CIS Benchmarks, DISA STIG (NDM SRG) and ISO/IEC 27001:2022, with versions
- [x] Posture and coverage scoring
- [x] Optional AI (Groq) for explanations and for proposals on undecided controls
- [x] Deterministic, verified remediation for confirmed vendors
- [x] Derived, verified remediation for unconfirmed vendors — the change worked out from the configuration
      itself, simulated on a copy (only where a removal can honestly resolve the control)
- [x] A resolution queue for UNKNOWN / NOT_CONFIGURED controls: teach a line, rescan, updated posture
- [x] React dashboard: scan, Results, Fix, Teach, All checks, Devices, Frameworks, Knowledge, History

## Stretch
- [x] Human-in-the-loop learning that persists (recognizers)
- [x] Backend AI assistant endpoints (no chat view yet)
- [ ] A third dedicated parser — deliberately not built; other vendors use the generic path
- [x] Per-device PDF compliance report (`POST /api/report`)
- [ ] Historical scan comparison
