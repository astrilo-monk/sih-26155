# Roadmap

Summary:

## Done
- [x] Cisco IOS and FortiGate parsers with grammar-coverage vendor confirmation (look-alikes stay unverified)
- [x] Secret redaction before every AI call
- [x] Control catalog (23 controls) with PASS / FAIL / UNKNOWN / NOT_CONFIGURED results and versioned NIST / CIS mappings
- [x] Posture + coverage scoring with bounds and critical controls not assessed
- [x] Security facts with assurance; every control runs on every configuration
- [x] Generic tokenizer and lexicon heuristics for unknown vendors (provisional, no AI needed)
- [x] Administrator-confirmed recognizers persisted (SQLite, or Postgres via `DATABASE_URL`) and reused across restarts
- [x] Shipped seed knowledge: 161 generalized recognizers for eleven unparsed dialects and AWS security groups
- [x] Structured (JSON) configurations flattened to one statement per object, so cloud rules are read and teachable
- [x] Serial number / model / OS version reported when the uploaded text states them
- [x] Scan history survives a restart: a redacted copy of each scan and its plans (`scans` table)
- [x] AI judge: budgeted, cached, citations verified, proposals never scored
- [x] Deterministic, vendor-aware remediation verified by rescan
- [x] Candidate remediation for unconfirmed vendors (typed, AI-proposed or derived), simulated on a copy
- [x] Seed write-back for unconfirmed vendors: the recognizer that read a failing line writes its secure form,
      verified by rescan to a decisive PASS; a typed or AI command joins the corrected configuration only when
      reviewed recognizers read every line of it
- [x] Framework views: NIST SP 800-53 Rev. 5, CIS (confirmed vendors), DISA NDM SRG, ISO/IEC 27001:2022 Annex A,
      one of them selectable at upload (default: all)
- [x] Per-device PDF compliance report
- [x] Sidebar UI (New scan, Overview, Devices, Findings, Remediation, Adaptive learning, Frameworks, History) with
      AI *Explain this* in the finding drawer
- [x] Optional shared API key (`API_KEY`) and configurable CORS origins

## Not implemented (possible next steps)
- [ ] Adding a *missing* setting (banner, syslog) for an unconfirmed vendor from a seed template. Held back: with
      no line in the file, nothing proves the dialect writes it that way (the PAN-OS `deviceconfig system
      syslog-server` seed appears in none of Batfish's real exports), the rescan only re-reads what the seed
      wrote, and some settings need a second object the seed cannot express (a PAN-OS syslog profile does
      nothing until a log-forwarding profile uses it). Prerequisite: seeds tagged by source, writing only from
      syntax seen in real exports
- [ ] Nokia SR OS seeds: Batfish's SR OS configs hold no management settings; needs real or lab exports
- [ ] Users and roles for review, recognizer and remediation endpoints (today: one optional shared key)
- [ ] Replay of new recognizers against archived scans (the archive holds results, not configurations)
- [ ] Pin the DISA SRG ids to a downloaded NDM SRG revision; CIS Controls v8 and PCI DSS mappings
- [ ] AI escalation for UNKNOWN controls of confirmed vendors (decide, or drop the legacy interpreter)
- [ ] Remove the deprecated `score` once no script depends on it
- [ ] Assistant chat view in the frontend
- [ ] `/api/assistant/status` that reflects an exhausted quota
