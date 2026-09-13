# NetAuditAI — Control-First Refactor Plan

Branch: `refc/complete-change`

The previous plan (adaptive parsing phases 1–6: unknown-line capture, AI
interpretation, confidence tiers, Training UI, learned mappings, adaptive
integration) is **complete** and lives in git history. This plan builds on it.

---

## Why we are changing direction

Findings from reading the current code:

1. **Unknown-vendor values are written but never evaluated.** 12 of 15 rules
   only run for `CISCO_IOS` / `FORTINET`. 19 of 35 fields in
   `FIELD_REGISTRY` are read by no rule at all, including
   `management.telnet_enabled`. `sample/unknown.cfg` line 71
   (`remote-console protocol telnet`) produces no finding even if the AI
   interprets it perfectly.
2. **Missing data becomes PASS or FAIL.** Rules that don't run add no
   penalty, so `100 − penalties` scores unassessed checks as passed.
   LOG-001 fails on an empty `remote_hosts` even when the logging line was
   simply never interpreted.
3. **The model can't say "unknown".** `telnet_enabled: bool = False` means
   "not known" and "disabled" look identical.
4. **Secrets go to Groq unredacted.** The relevance filter captures
   password/secret/key/community lines and nothing redacts them.
5. **The AI is the bottleneck.** Lines go out 10 at a time with the full
   field catalog; when quota runs out, unknown configs get no result.

## The decision

> Answer security questions about configurations. Only understand what
> those questions need.

- **Controls** (security questions) are what we evaluate and report.
- **Security facts** (scoped, cited, assurance-tagged) are what we extract,
  cache and learn.
- Existing Cisco/FortiGate parsers stay as the most trusted fact source.
- AI is an optional, budgeted escalation step, never required for a result.

---

# Target Design (reference for all phases)

## Pipeline

```text
raw config
  │
  ├─ [0] Ingest: line table + secret redaction map
  ├─ [1] Vendor identification (deterministic)
  │       fingerprint → run parser → parse-coverage check
  │       coverage high → vendor profile CONFIRMED, else UNVERIFIED
  ├─ [2] Structure (always): statement tokenizer → config tree + symbol index
  ├─ [3] Fact extraction (tiered, every fact cites lines)
  │       T1 vendor parser → NormalizedConfig → facts adapter   PARSER
  │       T2 admin-confirmed recognizers                         CONFIRMED
  │       T3 lexicon heuristics                                  HEURISTIC
  ├─ [4] Control evaluation: decision table per control kind
  ├─ [5] AI escalation (optional): UNKNOWN controls only, grouped by block,
  │       cached, citations verified deterministically          AI_VERIFIED
  ├─ [6] Review queue: confirm proposal → save recognizer → no AI next time
  ├─ [7] Scoring: posture + coverage
  ├─ [8] Framework views
  └─ [9] Remediation: confirmed vendor only, verified by full rescan
```

## Core objects

```text
Evidence        line_numbers, text, scope_path

SecurityFact    predicate, subject, scope, value, unit (null = unknown),
                assurance (PARSER | CONFIRMED | DEFAULT | HEURISTIC | AI_VERIFIED),
                evidence, provenance

Control         id (keep MGMT-001 etc.), question, kind, severity,
                needs: [predicates], applicability, decision params,
                mappings: [{framework, version, requirement_id}],
                remediation_keys

ControlResult   control_id, status (PASS | FAIL | NOT_CONFIGURED | UNKNOWN | N_A),
                assurance, proposed_status, facts, evidence, reason
```

`Finding` becomes a view of a `ControlResult` with status FAIL, so the API
and frontend keep working.

A predicate may exist **only if a control consumes it**.

## Decision tables

| Kind | Fact says bad | Fact says good | No fact, confirmed vendor | No fact, unknown vendor | Conflicting / unresolved |
|---|---|---|---|---|---|
| Prohibition (Telnet off) | FAIL | PASS | vendor default → PASS/FAIL | NOT_CONFIGURED (unscored) | UNKNOWN |
| Requirement (remote log) | FAIL (explicitly disabled) | PASS (validated value) | FAIL, shown "not configured" | NOT_CONFIGURED (unscored) | UNKNOWN |
| Threshold (timeout ≤ 10m) | FAIL | PASS | vendor default | NOT_CONFIGURED | UNKNOWN (incl. unknown unit) |
| Relational (mgmt ACL) | FAIL | PASS | needs parser facts | UNKNOWN | UNKNOWN |

**N/A** only when proven: the confirmed vendor lacks the concept, or the
admin declared a device profile. Absence is never N/A for unknown vendors.

## Assurance rules

- **Decisive** (counts in score): PARSER, CONFIRMED, DEFAULT (confirmed vendor only).
- **Provisional** (shown as "Suspected FAIL / Probable PASS", scored as UNKNOWN):
  HEURISTIC, AI_VERIFIED. One-click confirm turns them into a recognizer.
- Optional setting, off by default: corroborated heuristic **FAIL** may count.
  Heuristic **PASS** never counts.

## Scoring

```text
weights:   critical 10, high 6, medium 3, low 1
posture  = Σw(PASS) / Σw(PASS + FAIL) × 100     over decisive results; "—" if none
coverage = Σw(decided) / Σw(applicable)         applicable = everything except N/A
bounds   = posture if all unknowns fail … if all unknowns pass
flag     = any critical control unassessed
```

## AI rules

AI may: judge UNKNOWN control blocks, propose cited facts, draft recognizer
templates, explain decided findings, suggest a vendor as evidence.

AI must never: decide PASS from absence, activate a vendor profile, write
remediation, save recognizers, change a score directly, see unredacted
secrets, or be required for a scan to return results.

## Vendor rules

- Every control runs on every config. Vendor never decides *whether* auditing happens.
- A confirmed vendor profile selects: T1 parser facts, the defaults table,
  remediation recipes, vendor-specific benchmark mappings (CIS/STIG product IDs).
- A vendor is confirmed by the deterministic detector plus parse coverage, or
  by an admin. An AI vendor guess is evidence only.

---

# Phase Overview

| Phase | Name | Effort | Priority |
|---|---|---|---|
| 0 | Safety net | S | Must |
| 1 | Stop the leaks (redaction, detector, honest unknowns) | S | Must |
| 2 | Control catalog + ControlResult | M | Must |
| 3 | Scoring v2: posture + coverage | S | Must |
| 4 | Security facts + remove vendor gates | M | Must |
| 5 | Generic tokenizer + lexicon heuristics (offline unknown vendors) | M | Demo-critical |
| 6 | Recognizers + Training UI confirms proposals | M | Demo-critical |
| 7 | AI escalation rewire | M | Should |
| 8 | Remediation v2 | M | Should |
| 9 | Framework views + final demo | S | Should |

**Cut line if time runs out:** phases 0–6 give a complete, honest,
offline-capable demo. Phases 7–9 improve cost, remediation and presentation,
but the current AI path and remediation keep working until then.

Every phase must leave the full backend test suite green.

---

# Phase 0 — Safety Net

## Why

We're about to change what the engine returns. We need proof that Cisco and
FortiGate findings don't silently change.

## Tasks

1. Golden snapshot tests: for every file in `backend/tests/fixtures/`,
   `sample/cisco/`, `sample/frontinet/`, record the set of
   `(rule_id, severity, line_numbers)` findings the current engine produces.
2. Add a test marked `xfail` documenting the known defect:
   `sample/unknown.cfg` produces no Telnet result for lines 70–71.
3. Record the current test count as the baseline.

## Do not

- Change any engine, rule, parser or scoring code.

## Done when

- Snapshot tests pass on the current code.
- The xfail test exists and is referenced in this plan.

## Status: done

- Baseline before Phase 0: **248 passed, 2 skipped**.
- `backend/tests/snapshots/phase0_findings.json`: 30 Cisco/FortiGate files
  (fixtures, `sample/cisco/**`, `sample/frontinet/`), recorded through the
  scan API with AI off: vendor, score, `(rule_id, severity, line_numbers)`.
- `backend/tests/test_phase0_snapshots.py`
  - `test_known_vendor_findings_match_phase0_snapshot`
  - `test_unknown_cfg_reports_telnet_on_lines_70_71` — `xfail(strict=True)`;
    must start passing in Phase 5.
- Verified against a clean `git archive HEAD` export (pre-refactor engine):
  31 passed + 1 xfailed.
- Regenerate only deliberately:
  `python tests/snapshots/generate_phase0_snapshots.py --force` (refuses to
  overwrite without `--force`). It reads `tests/fixtures/*.cfg` only, so the
  `tests/fixtures/lookalikes/` configs are never snapshotted.

---

# Phase 1 — Stop the Leaks

## Why

Fixes the two most serious problems with the smallest change, before any
refactor.

## Tasks

### 1a. Secret redaction before AI

- New module `backend/app/ai/redaction.py`.
- Before any line or context is sent to Groq, replace secret values with
  typed placeholders: `<SECRET:password>`, `<SECRET:type7>`,
  `<SECRET:snmp-community>`, `<SECRET:psk>`, `<SECRET:key>`.
- Keep the type hint (weak-encoding controls need it), drop the value.
- Apply in `adaptive/interpreter.py` prompt building and in `api/routes/assistant.py`.

### 1b. Detector parse-coverage check

- After a known parser runs, compute the share of non-comment, non-blank
  lines it consumed. Parsers already know what they didn't recognize.
- Below threshold (start at 0.7, make it a setting) → treat vendor as
  UNVERIFIED: log it, flag it in the scan response, and route through the
  unknown-vendor path.
- Add a test with an IOS-like but foreign config (e.g. Arista-style
  `hostname`, `!`, `enable secret`, `ip access-list`) that must not be
  treated as confirmed Cisco IOS.

### 1c. Honest unknowns (interim, before Phase 2 statuses)

- For `Vendor.UNKNOWN` configs, absence-based rules (LOG-001, LOG-002
  "no servers" branch, BOUNDARY-002) must not produce a FAIL from an empty
  field. Mark the scan provisional with a reason instead.
- For unknown vendors, don't display a numeric score when no rule could
  evaluate real evidence; show "not assessed".

## Do not

- Change Cisco/FortiGate findings (Phase 0 snapshots must stay green).

## Tests

- Redaction: each secret type replaced; non-secret lines unchanged; AI mock
  receives no raw secret.
- Detector: foreign IOS-like config becomes UNVERIFIED; real fixtures stay confirmed.
- Unknown config with an uninterpreted logging line → no LOG-001 FAIL.

## Done when

- No raw secret reaches the AI client in any test.
- Snapshots green.

## Status: done

Suite after Phase 1: **443 passed, 2 skipped, 1 xfailed** (frontend 13 passed, build OK).
A strict audit of the first implementation found secret leaks, false vendor
confirmations and missing-data scoring paths; all are fixed below and covered
by tests.

Decisions and deviations:

- **1a** `app/ai/redaction.py`
  - `Redactor.line()`: typed placeholders keeping the storage type (`type7`).
    Covers whole-token and hyphenated compound keywords (`sso-password`,
    `ppk-secret`, `wpa-psk`, `message-digest-key` …), storage/mode words
    (`level 15`, `cipher`, `simple`, `ENC`), secrets with spaces (value runs to
    a known trailing option), `key=value`, `key: value`, JSON, XML,
    `snmp-server host … <community>`, `authentication text`, base64 key
    material including short padded tails.
  - Scope rule (FortiOS `set name` in an SNMP community block) uses each
    line's own block path: `UnrecognizedLine.context_before_paths` /
    `context_after_paths`; a missing path is treated conservatively.
  - `Redactor.scrub()` removes known values from free text.
  - Applied at all four Groq call sites: interpreter prompt (target, block path,
    context), explain-finding (evidence and text scrubbed with every secret in
    the scanned configs), chat (prose mode + known config secrets), summary
    (no config text).
  - `tests/test_phase1_redaction.py`: 43 cross-vendor leak cases, context-scope
    and prose cases, and every AI entry point with a mocked client.
- **1b** Coverage = **grammar conformance**, not `source_lines` (parsers only
  record lines they extract; FortiGate fixtures would score 0.29).
  - `app/parsers/coverage.py`, IOS: known roots; argument checks for
    case-sensitive interface names, `line` ranges, `username`, `enable`,
    `service`, `vrf`, `router`, `transceiver`, `password`, `ip access-list`;
    `no` forms checked the same way; `interface`/`line` children validated;
    children of non-block commands are foreign; every banner type's body covered.
  - FortiOS: balanced closed statement grammar **and** a FortiGate-only section
    (`config firewall` / `config vpn`), so FortiSwitchOS is not a FortiGate.
  - `detector.identify_vendor()` → `confirmed | unverified | unknown` with a
    `reason`. Unverified when: profile mismatch; ≥ `MAX_FOREIGN_RUN = 5`
    consecutive foreign top-level statements (pasted foreign blocks); or
    coverage < `vendor_parse_coverage_threshold` (0.7) with ≥
    `MIN_UNCOVERED_LINES = 3` foreign lines.
  - `tests/fixtures/lookalikes/`: Arista EOS, NX-OS, IOS-XR, ASA, Dell OS10,
    Brocade ICX, mixed IOS + foreign block, FortiSwitch → all unverified; an
    IOS-XE config with exec banner / `Virtual-PortGroup` / `iox` / `pnp` stays
    confirmed; all 30 Phase 0 files stay confirmed.
  - Response gains `vendor_identification[]` (status, coverage, reason);
    unverified configs take the unknown path with a provisional reason.
  - Remediation never re-parses an unconfirmed config: `/remediate`, `/verify`,
    `/download-fixed` return 409 for unknown/unverified vendors, and
    `apply_remediation` raises for anything but Cisco IOS / FortiGate.
- **1c** LOG-001 and both LOG-002 branches no longer fail from an empty field on
  `Vendor.UNKNOWN` (LOG-002 auth fails only on an applied explicit `false`).
  BOUNDARY-002 was already presence-based (`ip_source_route is True`), no change.
  "Not assessed" = unknown vendor with no findings and no applied value that a
  rule **actually evaluated** (`evaluated_fields(config)`; e.g. NTP
  authentication without a server is not evaluated) → `score: null`,
  `devices[].assessed`, `adaptive.assessed`, UI shows "— NOT ASSESSED".
- **Interim layer**, all tagged `INTERIM(phase1)` for removal with the Phase 2
  catalog: `BaseRule.absence_based`, `evaluated_fields()`, `_absence_is_evidence`,
  `_applied_value` (rules/base.py, logging_rules.py, boundary.py),
  `engine.ABSENCE_BASED_RULE_IDS` / `has_assessable_evidence`, the absence reason
  in `routes/scan.py`. API fields `devices[].assessed` / `adaptive.assessed` are
  superseded by Phase 3 posture/coverage.
  *(Removed in Phase 2 — replaced by ControlResult statuses. `_absence_is_evidence`
  and `_applied_value` remain as rule logic, retagged `INTERIM(phase4)`.)*
- Existing tests that asserted the old defect (LOG-001 FAIL / numeric score on
  unknown vendors) were updated deliberately, with explicit expectations (no
  assertion derived from implementation constants): `test_adaptive_generic`,
  `test_adaptive_api_integration`, `test_phase3_e2e`, `test_phase4_review_api`,
  `test_phase6_adaptive_e2e`.

Known limits (accepted, owned by later phases):

- One evaluated vendor-neutral value on an unknown vendor (e.g. only
  `ip_source_route = false`) still yields a 100 score — unassessed controls are
  not yet penalised. Fixed by Phase 3 posture + coverage.
- Redaction is pattern-based: an unkeyed secret in an unlisted syntax can still
  pass. The explain and chat paths also scrub every value collected from the
  scanned configs.
- The FortiGate parser yields a line-less SNMP community named after a nested
  `edit <id>` (pre-existing; not changed so Phase 0 snapshots stay identical).
- The IOS grammar is a curated root list: a real IOS config dominated by
  unlisted roots (e.g. Catalyst 9800 WLC `wireless` blocks) can come out
  unverified. The threshold is a setting.

---

# Phase 2 — Control Catalog + ControlResult

## Why

Rules already are security questions. Make that explicit so results can be
PASS / FAIL / NOT_CONFIGURED / UNKNOWN / N/A with evidence.

## Tasks

1. `backend/app/controls/catalog.py`: one entry per existing rule ID
   (MGMT-001…009, BOUNDARY-001…003, LOG-001…002, CRYPTO-001) with
   `question`, `kind`, `severity`, `mappings` (with framework **version**),
   `remediation_keys`.
2. `backend/app/models/results.py`: `Evidence`, `ControlResult`, status and
   assurance enums.
3. Wrap existing rules: each rule returns `ControlResult`s. Where a rule
   currently returns `[]`, return PASS (it had data and found nothing), N/A
   (confirmed vendor lacks the concept) or NOT_CONFIGURED / UNKNOWN (no data).
4. `Finding` is derived from FAIL results; existing API fields unchanged.
   Add `results[]` to the scan response.
5. Move compliance mappings out of rule code into the catalog. Verify each
   against the current framework version (e.g. LOG-002 cites NIST AU-8(1),
   which Rev 5 appears to have withdrawn into SC-45(1) — check).

## Do not

- Change which FAILs are produced (snapshots).
- Rewrite rule logic yet (Phase 4).

## Tests

- Every catalog control produces exactly one result per config (or one per scope).
- FAIL set equals Phase 0 snapshots.
- Unknown vendor: no control reports PASS without evidence.

## Done when

- API returns `results[]` with statuses; frontend still renders findings.

## Status: done

Suite after Phase 2: **587 passed, 2 skipped, 1 xfailed** (frontend 13 passed, build OK).
Phase 0 snapshots unchanged: all 30 Cisco/FortiGate FAIL sets identical.

- **Catalog** `app/controls/catalog.py`: 15 controls (ids kept) with title,
  question, kind (prohibition / requirement / threshold / relational), highest
  FAIL severity, category, remediation keys (the existing template ids), and
  `normalized_fields` (`INTERIM(phase4)`, replaced by predicates).
- **Mappings** carry framework + exact version; CIS items carry their vendor and
  are attached only to that vendor's findings.
  - NIST SP 800-53 Rev. 5 checked against the official OSCAL catalog, release
    5.2.0: every id exists with its official title, none withdrawn.
    **AU-8(1) is withdrawn (moved to SC-45(1))** — LOG-002 now cites AU-8,
    SC-45, SC-45(1). LOG-001 now cites AU-4(1) / AU-9(2) (off-box storage)
    instead of the generic AU-2 / AU-4.
  - CIS: the old CIS numbers did not match any benchmark (e.g. "1.4.1
    Configure remote syslog" is a password item). Replaced only with item ids
    confirmed for the exact benchmark version and level (Tenable audit files):
    Cisco IOS XE 17.x v2.2.1 L1/L2, v2.1.0 L1 (3.1.1); FortiGate 7.4.x v1.0.1
    L1/L2. Controls without a verified item have no CIS mapping — not a guess:
    Cisco MGMT-002, BOUNDARY-001, LOG-001, CRYPTO-001; FortiGate MGMT-005,
    MGMT-007, MGMT-008, BOUNDARY-002, BOUNDARY-003, CRYPTO-001. (IOS XE
    `logging host` / `ntp authenticate` ids were only found for 16.x.)
- **Results** `app/models/results.py`: `Status`, `Assurance`, `Evidence`,
  `FailureDetail`, `ControlResult`.
- **Rules** return ControlResults. `check()` keeps the original detection logic
  and returns FAILs (one per failing scope). `non_failure()` decides the rest:
  - PASS only with cited configuration lines; otherwise it degrades to UNKNOWN.
  - NOT_CONFIGURED when nothing relevant exists; UNKNOWN when something exists
    but cannot be decided (e.g. VTY without `transport input`, proposal without
    encryption, NTP server with unknown authentication, no WAN-role interface).
  - Platform defaults are not assumed: they yield NOT_CONFIGURED / UNKNOWN with
    a reason until the Phase 4 defaults table.
  - Vendor-gated rules: unknown vendor → UNKNOWN if an applied mapping touched
    the control's fields, else NOT_CONFIGURED (relational: UNKNOWN); FortiGate
    for Cisco-only MGMT-005 / MGMT-008 → UNKNOWN.
  - N/A is never emitted yet (nothing is *proven* not applicable).
  - A rule that raises yields UNKNOWN; the scan continues.
- **Assurance**: PARSER for confirmed vendors; for adaptive values the weakest
  cited mapping (learned / admin → CONFIRMED, AI auto-mapped → AI_VERIFIED).
- **Findings** = `controls/views.finding_from_result` over FAIL results;
  compliance from the catalog; `ComplianceMappingSchema.version` added
  (shown as a tooltip in `FindingDetail`).
- **API**: `results[]` on every scan response (display-only scans too —
  controls are deterministic), with control question, kind, status, assurance,
  scope, reason and evidence.
- **Interim layer removed**: `absence_based`, `evaluated_fields`,
  `has_assessable_evidence`, `ABSENCE_BASED_RULE_IDS`. The unknown-vendor score
  gate is now "any decided result"; the adaptive reason lists NOT_CONFIGURED /
  UNKNOWN controls. Legacy `score` unchanged otherwise (Phase 3).
- **Tests** `tests/test_phase2_controls.py`: catalog completeness, NIST ids and
  titles vs OSCAL 5.2.0, CIS vendor scoping, one result per control (or
  per-scope FAILs) on 30 snapshot files + 9 look-alikes + 2 unknown configs,
  no PASS without evidence, assurance, FAIL set = snapshot, unknown-vendor
  statuses, broken-rule containment, API `results[]`, catalog compliance on
  findings.

Known limits:

- An unknown-vendor NTP server with undetermined authentication is now UNKNOWN
  (not a scored pass), so such configs are "not assessed" unless another control
  decides — deliberate, stricter than Phase 1.
- CIS coverage is partial by design (verified items only).

---

# Phase 3 — Scoring v2

## Why

`100 − penalties` scores unassessed checks as passed.

## Tasks

1. `analysis/scoring.py`: add `posture`, `coverage`, `bounds`,
   `critical_unassessed` using the formulas in Target Design.
2. Only decisive assurance counts toward posture.
3. API: add the new fields; keep legacy `score` for one phase, marked deprecated.
4. Frontend (`ScoreOverview`, `ScoreGauge`): show posture, coverage and the
   critical-unassessed warning. Show "—" when nothing is decided.

## Tests

- All PASS → 100 posture, 100% coverage.
- All UNKNOWN → posture "—", coverage 0%.
- Critical UNKNOWN sets the flag.
- N/A excluded from coverage denominator.
- Existing scoring tests updated deliberately (this is a semantics change).

## Done when

- An unknown config with nothing decided can never show 100.

## Status: done

Suite after Phase 3: **597 passed, 2 skipped, 1 xfailed** (frontend 13 passed, build OK).

- `analysis/scoring.py`: `calculate_posture(device_results)` → `Posture`
  (`posture`, `coverage`, `bounds`, `critical_unassessed`), weights
  critical 10 / high 6 / medium 3 / low 1.
  - Results are collapsed per (device, control): per-scope FAILs count once at
    the worst failure severity, so one question never outweighs the others.
  - Only PARSER / CONFIRMED / DEFAULT verdicts are decided; HEURISTIC and
    AI_VERIFIED PASS/FAIL count as undecided (in coverage and bounds).
  - NOT_CONFIGURED and UNKNOWN are undecided; N/A leaves the denominator.
  - `critical_unassessed` lists catalog-critical controls left undecided.
- API: `posture`, `coverage`, `posture_bounds`, `critical_unassessed` on every
  scan response (display-only scans too). Legacy `score` / `calculate_score`
  kept, marked DEPRECATED; remediation before/after still uses it (Phase 8).
- Frontend: `ScoreOverview` shows posture ("—" when nothing decided), coverage,
  the fail/pass range and the critical-unassessed warning; the dashboard banner
  keys off `posture`. `ScoreGauge` is unused and was left alone.
- Tests `tests/test_scoring_v2.py`: all PASS, all UNKNOWN / NOT_CONFIGURED,
  provisional assurance, critical flag, N/A exclusion, weights + bounds,
  per-scope collapse, multi-device, API on `sample/unknown.cfg` (posture "—",
  coverage 0) and a Cisco fixture. Existing tests unchanged (legacy score kept).

Known limits:

- An AI-mapped value on an unknown vendor now yields posture "—" even when the
  legacy score is set — deliberate until recognizers (Phase 6) confirm it.

---

# Phase 4 — Security Facts + Remove Vendor Gates

## Why

Controls should run for every vendor. Vendor parsers become one source of facts.

## Tasks

1. `backend/app/facts/predicates.py`: the predicate vocabulary, only what the
   15 controls need. Starting set:

   ```text
   mgmt.remote_access.protocol_enabled   (subject: telnet|ssh|http|https)
   mgmt.remote_access.source_restricted  (scope: vty / interface)
   mgmt.ssh.version
   mgmt.session.idle_timeout             (unit required)
   auth.central_aaa.enabled
   auth.password.storage                 (subject: enable|user|console)
   snmp.community                        (value, permission, acl)
   snmp.v3.enabled
   log.remote.destination
   time.ntp.server
   time.ntp.authenticated
   banner.login.present
   boundary.source_routing.enabled
   boundary.discovery_protocol.enabled   (scope: interface)
   boundary.policy.permit_any            (scope: acl / policy)
   crypto.ipsec.encryption / hash / dh_group
   ```

2. `backend/app/facts/from_normalized.py`: adapter from `NormalizedConfig` to
   facts (assurance PARSER) for Cisco and FortiGate, with line citations from
   `source_lines`.
3. `backend/app/facts/defaults.py`: vendor defaults table (confirmed profiles only).
4. `backend/app/controls/evaluate.py`: generic decision-table evaluator per
   control kind. Re-express each rule as catalog data plus, where needed, a
   small predicate function.
5. **Shadow mode:** run old rules and new evaluator together; test that FAIL
   sets are identical on all fixtures. Then switch the engine to the new
   evaluator and delete the vendor-gated branches.

## Do not

- Write generic unknown-vendor extraction yet (Phase 5).
- Remove `NormalizedConfig`; it stays as the parser internal model.

## Tests

- Parity: new evaluator FAILs equal Phase 0 snapshots.
- Decision-table unit tests for each kind and each column.
- Property test: unknown vendor + no facts ⇒ never PASS, never FAIL.

## Done when

- `analysis/rules/*` no longer check `config.device.vendor` to decide whether to run.

---

# Phase 5 — Generic Tokenizer + Lexicon Heuristics

## Why

Unknown vendors must get useful, cited results with **no AI**.

## Tasks

1. Extend `adaptive/context.py` into `backend/app/structure/tokenizer.py`:
   every line becomes a `Statement(scope_path, key_tokens, values, polarity, line)`.
   Handle:
   - indentation, braces, `config`/`edit`/`next`/`end`
   - flat prefix blocks (consecutive lines sharing a leading token)
   - `set a b c` paths, `key=value` pairs, `/section` headers
   - negation: `no …`, `disable(d)`, `=no`, `false`, `off`, `delete`
2. `backend/app/structure/symbols.py`: named objects and their references
   (ACL names, address objects, policies).
3. `backend/app/facts/lexicon.py`: synonyms per predicate, seeded from
   `adaptive/relevance.py`. Examples: `secure-shell` → ssh;
   `remote-console` / `vty` / `admin-access` → remote access;
   `audit-stream` / `syslog` → remote log; `time-sync` / `ntp` → time.
4. `backend/app/facts/heuristics.py`: produce HEURISTIC facts only with
   - a predicate keyword and a typed value (IP, int, enum), and
   - polarity resolved from the same line or the same scope block, and
   - no conflicting candidate in scope (conflict → UNKNOWN with both cited).
5. Unknown-vendor path produces facts instead of writing into `NormalizedConfig`.
6. Frontend: show provisional results as "Suspected FAIL / Probable PASS"
   with evidence lines.

## Acceptance target: `sample/unknown.cfg`, offline

| Control | Expected | Evidence |
|---|---|---|
| Cleartext remote management | Suspected FAIL | 70, 71 |
| Management source restriction | UNKNOWN (conflict) | 67–68 vs 72 |
| SSH version | Probable PASS | 32 |
| Remote logging | Probable PASS (telemetry line 88 must not be confused) | 55 |
| Idle timeout | UNKNOWN (unit not stated) | 38 |
| NTP server + auth | Probable PASS | 59, 60 |
| Central AAA | Probable PASS | 48–50 |
| IPsec crypto | Probable PASS | 76–78 |
| SNMP | NOT_CONFIGURED | — |
| Login banner | NOT_CONFIGURED | — |

The Phase 0 xfail test now passes.

## Tests

- Tokenizer: one test per dialect shape above.
- Negation: `no ip http server`, `telnet disabled`, `disabled=yes`.
- Banner / description text containing "telnet" produces no fact.
- The acceptance table above, with AI mocked as unavailable.

## Done when

- `sample/unknown.cfg` gives the table above with zero AI calls.

---

# Phase 6 — Recognizers (Human-in-the-Loop Learning)

## Why

Every admin confirmation should permanently turn a provisional result into
a decisive one, with no AI call next time.

## Tasks

1. Migrate `learned_mappings`: add `predicate`, `subject`, `scope_template`,
   `dialect_fingerprint`, `negatives`. Mechanical migration table from the
   35 `normalized_field`s to predicates; keep old columns until Phase 7 ends.
2. Extend `adaptive/matcher.py` templates with typed slots:
   `{int}`, `{ip}`, `{duration}`, `{enum:name}`, `{polarity}`, plus a scope prefix.
   Still no raw regex.
3. Safety gates in `db/mappings.py` before saving:
   - at least 2 non-stopword literals
   - polarity must be a literal or `{polarity}` slot
   - `{duration}` needs a unit (admin picks it if the text has none)
   - **replay test**: run against stored past configs, show how many results change
   - conflict with an existing recognizer → reject (keep `MappingConflictError`)
   - dialect fingerprint overlap required by default
4. Recognizer facts get assurance CONFIRMED (decisive).
5. Training UI (`AdaptiveTraining.jsx`): queue of provisional results →
   Confirm / Edit / Reject. Confirm drafts a recognizer from the evidence
   line; the admin reviews the template and the replay diff.

## Tests

- Confirm Telnet on `unknown.cfg` → rescan → decisive FAIL, zero AI calls.
- Same recognizer on `remote-console protocol ssh` → PASS for telnet control.
- Stopword-only template rejected.
- Conflicting recognizers → UNKNOWN.
- Existing learned-mapping tests adapted, not deleted.

## Done when

- Demo loop works offline: scan → suspected → confirm → rescan → decisive, coverage goes up.

---

# Phase 7 — AI Escalation Rewire

## Why

Cut Groq usage to a few calls per config and make AI output verifiable.

## Tasks

1. `backend/app/ai/judge.py`: input = UNKNOWN controls + their redacted scope
   blocks; output = fact proposals with line citations. Group several controls
   per call; order by severity; stop at a per-scan budget setting.
2. Cache: key = hash(redacted block + control ids + prompt version + model),
   stored in SQLite. Identical blocks across a fleet cost one call.
3. Citation verifier (build on `mapper.assess_evidence` / `line_polarity`):
   cited line exists, value token present, polarity matches, scope consistent.
   Failures are discarded. Passes get assurance AI_VERIFIED (provisional).
4. AI can draft a recognizer template for the Training UI.
5. Keep `interpret_lines` behind a setting until parity tests pass, then
   retire it and the `FIELD_REGISTRY`-as-AI-vocabulary path.

## Tests (AI mocked)

- Budget exhausted → remaining controls UNKNOWN with reason, scan still returns.
- Cache hit → zero calls.
- Uncited or mismatched citation → discarded.
- AI claiming PASS from absence → discarded.

## Done when

- `sample/unknown.cfg`: at most 1–2 calls on first scan, zero after confirmations.

---

# Phase 8 — Remediation v2

## Why

Fixes must be safe, parameterized and truly verified.

## Tasks

1. Recipes keyed by `(control_id, vendor_profile)`; parameters bound from
   fact subject/scope (interface, vty range, policy id), replacing
   `_extract_interface_name` regex on evidence text.
2. Declare required inputs (syslog IP, NTP server, SNMPv3 credentials).
   Remove hard-coded `10.0.0.100` and fake `$9$…` values; a recipe with
   missing inputs is "needs input", never "verified".
3. No recipes for UNVERIFIED or unknown vendors: show vendor-neutral guidance
   plus framework references.
4. Apply as structured edits on the config tree, then rescan the full pipeline.
5. Verified only if: target control FAIL → PASS **and** no other control
   regressed **and** parse coverage did not drop.

## Tests

- Extend `test_remediation_e2e.py` with regression-detection cases.
- Recipe with missing input cannot be marked verified.
- Unknown vendor gets no commands.

## Done when

- Every "verified" fix passed the regression check with real inputs.

---

# Phase 9 — Framework Views + Final Demo

## Tasks

1. Framework view per framework: a requirement FAILs if any mapped control
   FAILs, PASSes only if all mapped controls PASS decisively, else partial/unknown.
   Per-framework coverage.
2. Mark requirements not auditable from device config as
   "not assessable from configuration"; exclude them. Never show "X compliant".
3. Vendor-specific benchmarks (CIS Benchmarks, product STIGs) apply only to
   confirmed vendors. Unknown vendors map to NIST SP 800-53, ISO/IEC 27001:2022
   Annex A, DISA Network Device Management SRG, CIS Controls v8.
4. Remove the deprecated legacy `score` field.

## Final SIH demo script

```text
1. Upload Cisco config        → decisive results, posture + coverage, verified fix
2. Upload unknown.cfg offline → suspected Telnet FAIL (lines 70–71), honest coverage
3. Confirm the suspected FAIL → recognizer saved (replay diff shown)
4. Rescan                     → decisive FAIL, coverage up, ZERO AI calls
5. Turn AI on                 → only leftover UNKNOWN blocks judged, cited
6. Switch framework view      → NIST / ISO / SRG, with "not assessable" labelled
```

---

# What Not To Build

- Ontology / RDF / knowledge graph or graph database
- SMT / Z3 / Datalog constraint solving, firewall reachability analysis
- Embeddings or vector database
- Local LLM, fine-tuning, or automatic learning from AI output
- New dedicated parsers for Juniper, Palo Alto, MikroTik, etc.
- AI-generated remediation
- A crosswalk of thousands of framework requirements (curate ~25–40 device-auditable controls)
- Configurable per-user scoring formulas

# Keep / Retire Summary

**Keep:** Cisco and FortiGate parsers, `NormalizedConfig` (parser internal),
`detector.py` (hardened), `context.py`, relevance vocabulary (as lexicon seed),
`matcher.py` template grammar, `db/mappings.py` safety mechanics, `vendor.py`
evidence-only logic, Groq client with key rotation, structured output schemas,
`assess_evidence` / `line_polarity`, remediation templates and apply-and-reparse,
Training UI, rule IDs, the test suite.

**Retire as primary path:** `FIELD_REGISTRY` as AI vocabulary, line-by-line
`interpret_lines`, unrecognized-line capture as the gate to assessment,
vendor-gated rule branches, `calculate_score` penalty model, AI writes into
`NormalizedConfig`, non-Optional security booleans, display-only scans when AI
is unavailable, regex parameter extraction in remediation, placeholder values
in "verified" fixes.

# Final Success Criteria

- [ ] Cisco/FortiGate FAIL findings unchanged from Phase 0 snapshots
- [ ] No raw secret ever reaches the AI
- [ ] Every control runs on every config
- [ ] Every result has status, assurance, evidence lines and a reason
- [ ] No PASS without evidence; no FAIL from missing data on unknown vendors
- [ ] Posture and coverage shown; unassessed never scores as passed
- [ ] `sample/unknown.cfg` gives useful cited results with AI off
- [ ] Admin confirmation makes the next scan decisive with zero AI calls
- [ ] AI calls per config bounded by a budget and cached
- [ ] Verified remediation includes a regression check
- [ ] Full backend test suite green at every phase
