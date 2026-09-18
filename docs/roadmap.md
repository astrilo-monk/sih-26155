# Roadmap

The implementation record is [plan.md](../plan.md). Summary:

## Done
- [x] Cisco IOS and FortiGate parsers with grammar-coverage vendor confirmation (look-alikes stay unverified)
- [x] Secret redaction before every AI call
- [x] Control catalog (15 controls) with PASS / FAIL / UNKNOWN / NOT_CONFIGURED results and versioned NIST / CIS mappings
- [x] Posture + coverage scoring with bounds and critical controls not assessed
- [x] Security facts with assurance; every control runs on every configuration
- [x] Generic tokenizer and lexicon heuristics for unknown vendors (provisional, no AI needed)
- [x] Administrator-confirmed recognizers persisted in SQLite and reused across restarts
- [x] AI judge: budgeted, cached, citations verified, proposals never scored
- [x] Deterministic, vendor-aware remediation verified by rescan
- [x] Framework views and the demo UI (Results, Fix, Teach, All checks, Devices, Frameworks, Learned, History)

## Not implemented (possible next steps)
- [ ] Authentication and roles for review, recognizer and remediation endpoints
- [ ] Persistent scan storage (today: memory only) and replay of recognizers against stored history
- [ ] Verified mappings for ISO/IEC 27001:2022, DISA SRGs, CIS Controls v8
- [ ] AI escalation for UNKNOWN controls of confirmed vendors (decide, or drop the legacy interpreter)
- [ ] Remove the deprecated `score` once no script depends on it
- [ ] Assistant chat view in the frontend
- [ ] `/api/assistant/status` that reflects an exhausted quota
