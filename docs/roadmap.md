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
- [x] Shipped seed knowledge: 165 generalized recognizers for eleven unparsed dialects and AWS security groups
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
- [x] Sidebar UI (New scan, Overview, Devices, Findings, Attack paths, Remediation, Adaptive learning, Frameworks,
      History, Rules catalog, Audit ledger) with AI *Explain this* in the finding drawer
- [x] Optional shared API key (`API_KEY`) and configurable CORS origins
- [x] Accuracy benchmark with labelled ground truth (planted 18/20, fixtures 70/87, 0 missed, 0 false alarms)
- [x] Prompt-injection fence on every configuration-carrying prompt
- [x] Attack paths, evidence chain per finding, field-by-field compare, fleet view, contextual risk, fix order
- [x] Hash-chained audit ledger; report PDF (or multi-device .zip) verification
- [x] Platform N/A (AWS security groups), rules catalog, executive PDF
- [x] Changes since the last audit, checks across devices, offline AI, CI command line with SARIF,
      organisation policy
- [x] LLDP on an interface an external zone holds is decided; PAN-OS password length decided from a reviewed
      factory default (`backend/data/factory_defaults.json`)
- [x] End-to-end browser test of the demo path

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
- [ ] PAN-OS login lockout seed: needs real syntax (none in `teach/` or Batfish)
- [ ] MGMT-010 cites only the first exposing service line, so a derived fix removes one service and fails its
      re-check; and removing the profile from the interface does not clear it
- [ ] Teach page: when a line is already read but the check still cannot decide, show that line and the reason
      instead of "couldn't find a line"
- [ ] Two-page architecture PDF in the repository
- [ ] `/api/assistant/status` that reflects an exhausted quota
