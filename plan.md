# NetAuditAI -Control-First Refactor Plan

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
posture  = Σw(PASS) / Σw(PASS + FAIL) × 100     over decisive results; "-" if none
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

# Phase 0 -Safety Net

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
  - `test_unknown_cfg_reports_telnet_on_lines_70_71` -`xfail(strict=True)`;
    must start passing in Phase 5.
- Verified against a clean `git archive HEAD` export (pre-refactor engine):
  31 passed + 1 xfailed.
- Regenerate only deliberately:
  `python tests/snapshots/generate_phase0_snapshots.py --force` (refuses to
  overwrite without `--force`). It reads `tests/fixtures/*.cfg` only, so the
  `tests/fixtures/lookalikes/` configs are never snapshotted.

---

# Phase 1 -Stop the Leaks

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
  `devices[].assessed`, `adaptive.assessed`, UI shows "-NOT ASSESSED".
- **Interim layer**, all tagged `INTERIM(phase1)` for removal with the Phase 2
  catalog: `BaseRule.absence_based`, `evaluated_fields()`, `_absence_is_evidence`,
  `_applied_value` (rules/base.py, logging_rules.py, boundary.py),
  `engine.ABSENCE_BASED_RULE_IDS` / `has_assessable_evidence`, the absence reason
  in `routes/scan.py`. API fields `devices[].assessed` / `adaptive.assessed` are
  superseded by Phase 3 posture/coverage.
  *(Removed in Phase 2 -replaced by ControlResult statuses. `_absence_is_evidence`
  and `_applied_value` remain as rule logic, retagged `INTERIM(phase4)`.)*
- Existing tests that asserted the old defect (LOG-001 FAIL / numeric score on
  unknown vendors) were updated deliberately, with explicit expectations (no
  assertion derived from implementation constants): `test_adaptive_generic`,
  `test_adaptive_api_integration`, `test_phase3_e2e`, `test_phase4_review_api`,
  `test_phase6_adaptive_e2e`.

Known limits (accepted, owned by later phases):

- One evaluated vendor-neutral value on an unknown vendor (e.g. only
  `ip_source_route = false`) still yields a 100 score -unassessed controls are
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

# Phase 2 -Control Catalog + ControlResult

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
   which Rev 5 appears to have withdrawn into SC-45(1) -check).

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
    **AU-8(1) is withdrawn (moved to SC-45(1))** -LOG-002 now cites AU-8,
    SC-45, SC-45(1). LOG-001 now cites AU-4(1) / AU-9(2) (off-box storage)
    instead of the generic AU-2 / AU-4.
  - CIS: the old CIS numbers did not match any benchmark (e.g. "1.4.1
    Configure remote syslog" is a password item). Replaced only with item ids
    confirmed for the exact benchmark version and level (Tenable audit files):
    Cisco IOS XE 17.x v2.2.1 L1/L2, v2.1.0 L1 (3.1.1); FortiGate 7.4.x v1.0.1
    L1/L2. Controls without a verified item have no CIS mapping -not a guess:
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
- **API**: `results[]` on every scan response (display-only scans too -
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
  decides -deliberate, stricter than Phase 1.
- CIS coverage is partial by design (verified items only).

---

# Phase 3 -Scoring v2

## Why

`100 − penalties` scores unassessed checks as passed.

## Tasks

1. `analysis/scoring.py`: add `posture`, `coverage`, `bounds`,
   `critical_unassessed` using the formulas in Target Design.
2. Only decisive assurance counts toward posture.
3. API: add the new fields; keep legacy `score` for one phase, marked deprecated.
4. Frontend (`ScoreOverview`, `ScoreGauge`): show posture, coverage and the
   critical-unassessed warning. Show "-" when nothing is decided.

## Tests

- All PASS → 100 posture, 100% coverage.
- All UNKNOWN → posture "-", coverage 0%.
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
- Frontend: `ScoreOverview` shows posture ("-" when nothing decided), coverage,
  the fail/pass range and the critical-unassessed warning; the dashboard banner
  keys off `posture`. `ScoreGauge` is unused and was left alone.
- Tests `tests/test_scoring_v2.py`: all PASS, all UNKNOWN / NOT_CONFIGURED,
  provisional assurance, critical flag, N/A exclusion, weights + bounds,
  per-scope collapse, multi-device, API on `sample/unknown.cfg` (posture "-",
  coverage 0) and a Cisco fixture. Existing tests unchanged (legacy score kept).

Known limits:

- An AI-mapped value on an unknown vendor now yields posture "-" even when the
  legacy score is set -deliberate until recognizers (Phase 6) confirm it.

---

# Phase 4 -Security Facts + Remove Vendor Gates

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

## Status: done

Suite after Phase 4: **652 passed, 2 skipped, 1 xfailed** (frontend unchanged).
Shadow mode before the switch -old rules vs new evaluator on 42 configs (30
snapshot files, 9 look-alikes, `sample/unknown.cfg`, `sample/paloalto.cfg`,
`fortigate_broken_snmp_remediation.cfg`): **0 FAIL differences, 0 status
differences**. Then `app/analysis/rules/` was deleted. Phase 0 snapshots unchanged.

- **Facts** `app/facts/predicates.py`: 16 predicates, each consumed by a control
  (test-enforced); `SecurityFact` (predicate, subject, scope, value, unit,
  assurance, evidence, provenance). Value `None` = present but undetermined;
  `NOT_SET` = a confirmed parser read the config and the setting is absent (the
  consuming control decides what absence means).
  - Deviations: `crypto.ipsec.proposal` is one fact per proposal
    (`{encryption, hash, dh_group}`) so a proposal keeps one FAIL listing all its
    weaknesses; `snmp.v3.enabled` dropped (no control consumes it);
    `auth.password.encryption_service` added (MGMT-005 needs it).
- **Adapter** `app/facts/from_normalized.py` holds all vendor knowledge.
  - Cisco IOS / FortiGate: facts from the parser model with the exact Phase 0
    citations; assurance PARSER, or the weaker assurance of adaptive mappings on
    the cited lines. Several Cisco VTY ranges answer as one scope (first offending
    range), keeping one finding.
  - Other vendors: one fact per applied mapped field (lists collect their items,
    conflicting scalars → value `None` → UNKNOWN).
  - `PARSER_COVERAGE`: the FortiGate parser does not read password storage or AAA,
    so MGMT-005 / MGMT-008 are UNKNOWN for FortiGate.
- **Defaults** `app/facts/defaults.py`: FortiOS `admintimeout 5`,
  `admin-ssh-v1 disable`, `pre-login-banner disable`, `ip-src-routing disable`.
  Confirmed vendors only, only when a control has no fact at all. Cisco defaults
  are deliberately absent (reasons in the file): `ip source-route` / `ip ssh
  version` differ by release and would add FAILs; `exec-timeout` must be explicit
  (CIS 1.2.7 / 1.2.8).
- **Evaluator** `app/controls/evaluate.py` + `app/controls/judges.py`: catalog
  `needs` replaces `normalized_fields`; one judge per control turns a fact into
  PASS / FAIL / UNKNOWN; generic combination: one FAIL per failing scope > UNKNOWN >
  PASS (a cited line required unless DEFAULT) > NOT_CONFIGURED (UNKNOWN for
  relational). The vendor only selects recommendation wording. Extraction or
  judge errors → UNKNOWN; the scan continues.
- **Deliberate semantics changes** (tests updated with explicit expectations:
  `test_phase2_controls`, `test_phase3_e2e`, `test_adaptive_generic`,
  `test_phase6_adaptive_e2e`):
  - Unknown vendors: every applied mapped value is evaluated by its control
    (AI-mapped SSHv1 → MGMT-007 FAIL `ai_verified`; confirmed Telnet mapping →
    MGMT-001 FAIL `confirmed`). AI verdicts stay provisional (posture "-"); the
    deprecated legacy score counts them.
  - FortiGate silent on `admintimeout` / `admin-ssh-v1` / `ip-src-routing` → PASS
    DEFAULT; silent on `pre-login-banner` → FAIL DEFAULT. No snapshot file is
    silent on these.
  - Unclassified password storage (e.g. Cisco `enable password` without a type)
    → UNKNOWN instead of PASS.
  - The idle-timeout bound (> 15 min fails) applies to every source, not only
    FortiGate `admintimeout`.
- **Remediation**: FortiGate `set` templates now add a key the config does not
  state to the template's top-level block (reachable through the banner default);
  `test_fortinet_banner_fix_is_added_when_the_default_applies`.
- **Tests** `tests/test_phase4_facts.py`: vocabulary = control needs; rules package
  gone and judges never compare the vendor; parser facts cited; decision table per
  kind (prohibition, requirement, threshold, relational); one FAIL per scope; PASS
  without a line → UNKNOWN; weakest assurance; unknown vendor + no facts ⇒ never
  PASS/FAIL (every control × UNKNOWN / PALO_ALTO); unread predicate → UNKNOWN;
  FortiOS defaults PASS and FAIL; mapped facts (AI Telnet, conflict, list
  collection); API answers every control.

Known limits:

- Cisco VTY / console without `exec-timeout` still FAILs although IOS defaults to
  10 minutes (parity; CIS requires it explicitly).
- Interface WAN / external detection is still the parser heuristic, at PARSER assurance.
- Finding descriptions are vendor-neutral now (scope names the object);
  recommendations keep vendor wording.
- `ControlResult.facts` is populated but not yet exposed by the API.
- The Phase 0 xfail (Telnet on `sample/unknown.cfg` with AI off) is unchanged -
  it needs Phase 5 heuristics.

---

# Phase 5 -Generic Tokenizer + Lexicon Heuristics

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
| SNMP | NOT_CONFIGURED | -|
| Login banner | NOT_CONFIGURED | -|

The Phase 0 xfail test now passes.

## Tests

- Tokenizer: one test per dialect shape above.
- Negation: `no ip http server`, `telnet disabled`, `disabled=yes`.
- Banner / description text containing "telnet" produces no fact.
- The acceptance table above, with AI mocked as unavailable.

## Done when

- `sample/unknown.cfg` gives the table above with zero AI calls.

## Status: done

Suite after Phase 5: **674 passed, 2 skipped, 0 xfailed** (frontend 13 passed, build OK).
The Phase 0 xfail is now a normal passing test. Phase 0 snapshots unchanged
(heuristics never run for confirmed vendors).

- **Tokenizer** `app/structure/tokenizer.py`: `Statement(line, text, scope_path,
  key_tokens, values, polarity)`. Scope reuses `adaptive/context.structural_paths`
  (indentation, braces, `config`/`edit`/`next`/`end`), plus `/section` headers and
  flat prefix blocks (consecutive lines, no blank line between, same leading keyword).
  Tokens: `set` dropped, `key=value` split, IPs / numbers (with attached unit) /
  quoted strings are values. Polarity: `no`/`unset`/`delete`/`undo`,
  `enable(d)`/`disable(d)`/`on`/`off`/`true`/`false`/`yes`/`no`, switches
  (`disabled=yes`, `enabled=no`), self-negating keywords (`disable-telnet no`).
  Descriptions, remarks, comments and banner bodies never yield keywords.
- **Lexicon** `app/facts/lexicon.py`: synonym sets per predicate, matched on whole
  tokens or hyphen parts, never substrings.
- **Heuristics** `app/facts/heuristics.py`: one extractor per predicate (all except
  password storage); HEURISTIC facts citing their lines. Polarity from the line, else
  the block's state line (`remote-console state enabled`). Protocols need a
  management context before them (or a server form) and are ignored inside traffic
  rules. Candidates for the same (predicate, subject, scope) that disagree → one
  undetermined fact citing all → UNKNOWN "Conflicting statements on lines …".
- **Integration** (`facts_from_config`, unknown / unverified vendors only):
  admin-confirmed mappings answer their (predicate, subject); heuristics fill the rest.
  An AI mapping and a heuristic are both provisional: when they disagree the fact is
  undetermined (UNKNOWN citing both). Found in a live run: a partially rate-limited AI
  read `legacy-access disabled` as Telnet off and hid the suspected Telnet FAIL. The adaptive
  AI path still writes `NormalizedConfig` (retired in Phase 7) -task 5 is satisfied
  for the offline path, which produces facts only.
- **Scan route**: display-only now only when AI is unavailable, nothing is applied
  **and** heuristics find nothing.
- **Scoring**: heuristic verdicts stay undecided in posture / coverage; the deprecated
  legacy `score` ignores them too (a heuristic PASS never counts). AI verdicts keep
  counting in the legacy score, as in Phase 4.
- **API / frontend**: `findings[].assurance`; `ProvisionalResults` panel lists
  "Suspected FAIL / Probable PASS" with evidence lines; findings table marks
  heuristic / AI findings "Suspected".
- **Acceptance** (`tests/test_phase5_heuristics.py`, AI mocked unavailable, zero calls):
  table above exact -MGMT-001 FAIL [70, 71], MGMT-003 UNKNOWN [67, 68, 72], MGMT-007
  PASS [32], LOG-001 PASS [55], MGMT-006 UNKNOWN [38], LOG-002 PASS [59, 60],
  MGMT-008 PASS [48–50], CRYPTO-001 PASS [76–78], MGMT-004 / MGMT-009 NOT_CONFIGURED;
  posture "-", coverage 0. Plus tokenizer shape, negation, free-text, traffic-rule,
  mapping-precedence and never-scored tests.
- **Deliberate test updates** (unknown vendors with AI off are no longer empty):
  `test_phase0_snapshots` (xfail removed), `test_phase1_honest_unknowns`,
  `test_phase2_controls`, `test_phase3_e2e`, `test_phase4_review_api` (display-only
  case stubs heuristics to nothing), `test_adaptive_generic`.

Verification pass (offline scan of unknown.cfg + every fixture / sample, zero AI calls)
found three false-PASS paths, fixed; suite now **677 passed, 2 skipped**:

- A block's state line leaked into a *different* blank-separated block with the same
  prefix (`remote-console state disabled` … blank … `remote-console protocol telnet`
  → probable Telnet PASS). `Statement.block` (first line of the flat block) now
  separates them.
- Separate IPsec blocks with the same prefix merged into one proposal, hiding a
  DES / MD5 block behind the first block's values. Proposals now group per block
  (scope `secure-channel at line 75`); `dhgrp` added to the DH lexicon.
- Log / NTP / AAA server lines inside a disabled block (`syslog state disabled`)
  yielded destinations. Server candidates now respect the block state.

Skipped:

- `structure/symbols.py` (named objects and references): no control or heuristic
  consumes it yet. Add it with Phase 8 parameter binding or a relational heuristic
  that needs ACL-name resolution.

Known limits:

- Lexicon words can mislead on real vendors: Cisco ASA `http server enable` (ASDM
  over HTTPS) is a suspected MGMT-002 FAIL. Provisional by design; Phase 6
  confirm / reject fixes it per dialect.
- Source-restriction conflicts are config-wide, not per scope (`management-plane`
  vs `remote-console` conflict in `unknown.cfg`, as the table requires).
- A bare statement without polarity (`ntp authenticate`, `aaa new-model`,
  `transport input telnet` with no block state) yields no fact.
- NTP servers and log hosts must be IP addresses (hostnames are not typed values).

---

# Phase 6 -Recognizers (Human-in-the-Loop Learning)

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

## Status: done

Suite after Phase 6: **697 passed, 2 skipped** (frontend 14 passed, build OK).

- **Migration v2** (`db/database.py`): `learned_mappings` gains `predicate`, `subject`,
  `scope_template`, `dialect_fingerprint`, `negatives` (JSON). Old columns kept. Field
  mappings get their predicate from `FIELD_PREDICATES` (moved to `facts/predicates.py`,
  19 of 35 fields; the rest feed no control) when read and when saved.
- **Typed slots** (`adaptive/matcher.py`, method `recognizer`): `{int}`, `{ip}`,
  `{duration}` / `{duration:<unit>}`, `{enum:<name>}`, `{polarity}`, plus `{any}`; at most one
  slot; still compiled from escaped literals, no raw regex. The field-mapping matcher ignores
  recognizers. A recognizer's `constant_value` is JSON: the value of a slot-less template, or an
  enum table (`{"telnet": true, "*": false}`).
- **Gates** (`facts/recognizers.validate_recognizer`, run by `db/mappings.validate_mapping`):
  ≥ 2 keywords besides stopwords; boolean predicates need a polarity literal (value must agree
  with it), a `{polarity}` slot or an enum true/false table; `{duration}` needs a unit in the
  text or the slot; value predicates need their slot type; template must match its example
  line; identical template + scope conflicts (`MappingConflictError`). Replay runs on draft and
  save and reports changed results. Dialect overlap (≥ 50 % of the smaller top-level keyword set)
  is required unless the admin picks "any dialect". SNMP community / IPsec proposal (dict values)
  are not recognizable yet.
- **Facts** (`facts_from_config`, unknown vendors): recognizer matches → CONFIRMED facts
  (conflicting recognizers → UNKNOWN citing both). A disabled block turns a boolean off and
  drops values. Heuristics and AI mappings skip the lines a recognizer answered or an admin
  rejected; other lines still speak, so a recognizer never hides a contradicting statement
  elsewhere. `AdaptiveService` no longer sends recognized lines to the AI.
- **API** (`routes/adaptive.py`): `GET /adaptive/scans/{id}/provisional` (undecided or
  provisional results with the heuristic lines behind them), `POST …/recognizers/draft`
  (drafted template + admin edits → gate errors + replay diff), `POST …/recognizers` (save,
  re-evaluate), `POST …/provisional/reject` (line recorded as rejected; heuristics and AI
  ignore it).
- **Training UI**: `RecognizerQueue` in the Training tab -Confirm drafts a recognizer
  (template / scope / value JSON editable, Re-check shows gate errors and the replay diff),
  Save Recognizer, Reject. The mapping table lists recognizers by predicate.
- **Tests** (`tests/test_phase6_recognizers.py`, AI mocked unavailable): confirm Telnet on
  `unknown.cfg` → rescan → decisive FAIL [70, 71], coverage 0 → > 0, zero AI calls; same
  recognizer on `remote-console protocol ssh` → confirmed PASS; admin picks a unit for line 38;
  reject removes the heuristic; gate cases (stopword-only, one keyword, missing / contradicting
  polarity, enum without table, wrong slot, no unit, no match); conflicting recognizers →
  UNKNOWN [30, 70, 71]; fingerprint / any-dialect; negatives; disabled block; recognized lines
  not sent to AI; v1 database migration. Existing learned-mapping tests pass unchanged;
  `test_phase4_review_api` patches `facts_from_config` instead of `heuristic_facts`.

Known limits:

- Replay covers the configs of scans held in memory by this process (scans are not persisted).
- Recognizers apply to unknown / unverified vendors only; confirmed vendors keep parser facts.
- A drafted template keeps the line's other values literal (`… allowed-source 10.44.100.0/24`
  with a constant is rejected by the polarity gate); the admin edits it or confirms another line.

---

# Phase 7 -AI Escalation Rewire

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

## Status: done (committed as `feat/ phase 7 ai judge`)

Suite: **759 passed, 2 skipped**; frontend 14 passed, build OK. Phase 0 snapshots unchanged (32 passed).
One live Groq call on a synthetic config: 3 controls sent, fake secret absent (a banner reusing it was scrubbed),
2 proposals accepted, a unitless `600` idle timeout rejected, 0 status changes.

A first validation found the verifier accepted any on/off line or number in the excerpt (NTP authentication
from `time-sync state enabled`, SSH version from `login-retries 1`), AI facts answered controls that never asked
(an http fact from MGMT-001 passed MGMT-002), AI verdicts moved the legacy score / findings / assessed, blank-line
blocks merged scopes, per-line redaction leaked reused and unknown-vendor secrets, and useless answers were
cached forever. Fixed as below.

- **Judge** `app/ai/judge.py`: targets UNKNOWN results citing a line the lexicon reads as one of the
  control's AI-readable settings (MGMT-001 telnet / MGMT-002 http subjects only). Excerpt = each cited line's
  tokenizer scope: its block siblings (same scope path and flat block, nearest 15) plus enclosing block
  headers -never blank-line paragraphs. The whole config is redacted first (so every secret is known), then
  every excerpt and the prompt are `Redactor.scrub`bed as a whole. Up to 4 controls per call, most severe
  first; `ai_judge_max_calls_per_scan` (default 2) shared by a scan; an exhausted quota zeroes it. A control
  left unjudged gets `(AI: …)` appended (budget used up / unavailable / no verifiable citation). The scan
  route catches any judge exception (the scan still returns).
- **Cache**: migration v3 `ai_judge_cache`, key = sha256(prompt version `judge-v2` + model + system prompt +
  prompt). Relative line refs, so identical scopes across a fleet are one call. Only answers with at least one
  verified proposal are stored; a cached answer is re-verified, and one that verifies to nothing (or is not a
  list) is not a hit -the judge asks again and overwrites it.
- **Verifier** (deterministic, per proposal): control asked; predicate needed and AI-readable; line refs all
  valid (any out-of-range, zero or negative ref rejects the proposal); quoted evidence on a cited line; every
  cited setting line is read by the lexicon heuristics (`heuristic_candidates`) as this predicate and subject
  with the same value (bool, SSH version, timeout converted to minutes from the AI's unit, address); other cited
  lines may only be that reading's block state lines; all setting lines in one tokenizer scope (a top-level
  line is its own scope). Passing proposals → `config.ai_facts`, AI_VERIFIED, `control_id` = the asking control.
- **Authority**: `SecurityFact.control_id` -the evaluator gives an AI fact only to its control. Any PASS / FAIL
  whose weakest evidence is AI_VERIFIED (judge facts and legacy `ai_auto_mapped` mappings, confirmed vendors
  included) is reported as UNKNOWN with `proposed_status` and no failure: no finding, no severity count, no
  legacy score, no `assessed`, no posture / coverage, no remediation. `_is_assessed` counts decisive assurance
  only. The frontend provisional table shows `proposed_status`.
- **Recognizer drafts** (task 4): verified AI facts of a control are candidate lines in that control's
  provisional queue, draft and reject endpoints; the template is drafted deterministically. A rejected or
  hallucinated citation never becomes an AI fact, so it cannot reach Training.
- **Redaction** (Phase 1 extended): `pwd`, `passcode`, `credential(s)`, `hash`, `*-pass`, `*-credential`,
  `*-token`, `auth-string`, `*community*` / `community-string`, and `neighbor|peer … md5 <key>`.
- **Legacy path** (task 5): retired for unknown vendors in the final improvement below. The conftest
  `no_real_ai_judge` fixture keeps the judge off the network in every test.
- **API**: `adaptive.ai_calls`, `adaptive.ai_cache_hits`. The scan route reads the new settings from
  `app_config.settings` at call time (a config reload replaces the settings object).
- **Tests** `tests/test_phase7_ai_judge.py` (62, AI mocked): 5 accepted and 21 discarded proposals (unrelated
  enabled / disabled line, unrelated numbers, a number smuggled from a sibling line, shared keyword
  `http-proxy`, another control's subject, hallucinated / zero / negative / missing refs, wrong quote, reversed
  polarity, another block's state line, separate scopes, invented / wrong unit, other address, unneeded
  predicate, control not asked); unrelated citation discarded end to end; excerpt = tokenizer scope in a
  config without blank lines, and two scopes never form one block; ineligible controls never sent; confirmed
  vendors never escalated; an AI fact read only by its control; AI PASS and FAIL leave score, findings, severity
  counts, assessed and posture unchanged (engine and scan API vs AI off); an AI mapping on Cisco is a proposal,
  not a finding; 1 call then fleet cache hits; budget / quota; empty, all-rejected, malformed and invalid
  answers never cached; a poisoned cache entry is re-verified and asked again; verified line drafts a
  recognizer; hallucinated / unrelated lines absent from the queue, draft and reject 404; 12 unknown-vendor
  secret syntaxes redacted and none -nor a value reused on a neighbour line -in the prompt.

### Final improvement: unfamiliar syntax, NOT_CONFIGURED discovery, legacy retirement

- **Unfamiliar syntax**: an UNKNOWN control without a lexicon-read line sends at most 3 lines naming related
  vocabulary (`lexicon.*_RELATED`, never limits / counters / lockouts in `UNRELATED`), each with its tokenizer
  scope. A cited line the lexicon does not read must itself be related to the predicate (subject by name) and state
  the proposed value: its own or its block's polarity, the number with a unit word written on the line (a
  converted `600 s` for `lock-after 10 minutes` is rejected), an address or hostname token. `lock-after 10 minutes`
  → proposed idle timeout; `max-sessions 10` and `lock-after 3 failures` never.
- **NOT_CONFIGURED discovery**: the judge also takes NOT_CONFIGURED results, ranked after every UNKNOWN control,
  with only related lines and a `task: discover` marker; same redaction, scope, verifier, control binding and cache
  (`judge-v4`). A verified fact makes the control UNKNOWN (a proposed PASS / FAIL when its judge decides, else no
  proposal: an NTP server without authentication stays UNKNOWN). No verified citation leaves NOT_CONFIGURED and
  its reason untouched. Absence cannot be cited; an empty config sends nothing. NTP / log destinations may be
  dotted hostnames that are a value of the cited line (not its leading keyword).
- **Legacy audit**: `ai_legacy_line_interpreter` and the unknown-vendor legacy branch are removed (the judge replaces
  them), as are `interpret_config` and the `legacy_line_interpreter` fixture. `adaptive_ai_for_known_vendors`
  (default off) remains: the judge never escalates confirmed vendors, so it cannot replace that path. It is
  isolated: `AdaptiveService` passes `auto_apply=False`, so every interpretation (HIGH included) goes to the review
  queue and only an administrator's accept / edit writes the config. `interpret_lines`, the mapper's interpretation
  path and the Phase 4 review API stay for it. Tests of unknown-vendor AI interpretation through the scan API were
  deleted (integration B/C/H, Phase 3 e2e 1/3/6/7, the Phase 6 unknown-vendor demo) or moved: interpreter / mapper
  safety to unit level (`test_adaptive_generic`), the review API and scan redaction onto a confirmed Cisco config
  with the flag on, learned-vs-AI masking to the service.
- **Validation**: backend 795 passed, 2 skipped (Phase 0 32, Phases 1–6 513, Phase 7 106, API / e2e 126 + 2
  skipped, remediation 41); frontend 14 passed, build OK. One live Groq call on a synthetic config with fake
  secrets asked 4 controls (3 as discovery). No secret was in the prompt. Verified: `admin-gui allowed-networks`
  (MGMT-003 proposed PASS), `operator lock-after 10 minutes` (MGMT-006 proposed PASS), a login message
  (MGMT-009 proposed PASS) and an NTP hostname (LOG-002 UNKNOWN, no proposal). The AI's "NTP authenticated" from
  `authentication-key <SECRET>` was rejected. PASS / FAIL set, posture, coverage, score, findings and assessed
  were unchanged. An earlier run spelled the unit `minutes` and was rejected, so the verifier now normalizes the
  AI's unit label (the line must still write the unit word).

Known limits:

- The legacy interpreter, the `FIELD_REGISTRY` AI vocabulary, the mapper's auto-apply (`map_interpretations`, now
  without a production caller) and the line review queue remain for `adaptive_ai_for_known_vendors`. Delete them
  together once confirmed-vendor escalation is decided (judge for parser-UNKNOWN controls, or drop the option).
- Discovery and unfamiliar-syntax targeting read related vocabulary only, at most 3 lines per control: a setting
  named with words outside it is never sent. Hostnames are accepted by shape, never resolved.
- Vendor evidence (`assess_vendor_evidence`) has no AI records on unknown vendors any more: it reports unknown.
- An AI PASS next to an undetermined heuristic still reports plain UNKNOWN without a proposal (evaluator
  precedence).
- Redaction is pattern-based: an unknown vendor's secret keyword outside the lexicon can still leak.
- Two AI proposals of one control on different lines combine into one fact; rejecting either line drops both.
- Heuristic suspected FAILs still count in `total_findings` (Phase 5 behaviour, unchanged here).
- The frontend does not show `ai_calls` / `ai_cache_hits` yet.

---

# Phase 8 -Remediation v2

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

## Status: done

Suite after Phase 8: **827 passed, 2 skipped** (frontend 16 passed, build OK). Phase 0 snapshots unchanged.

- **Recipes** `app/remediation/recipes.py`: `RECIPES[(control_id, vendor)]` for Cisco IOS and FortiGate -28
  recipes over all 15 controls (MGMT-005 / MGMT-008 Cisco only: the FortiGate parser never decides them). A recipe
  gets the control's decisive FAIL results and the parser model and returns edited lines. Parameters come from the
  parser model and the results' cited lines (VTY ranges, interfaces, proposals, communities), never from evidence
  text; `_extract_interface_name` is gone. Edits are local: a setting is replaced in place with its indentation, or
  added as the last child of its block (Cisco indented children; FortiOS `config/edit` tree with `next/end`), or
  before the final `end`. Comments and unrelated lines are untouched; CRLF and the trailing newline are kept. The
  FortiGate SNMP nested-block remover is kept verbatim (`remove_default_snmp_communities`).
- **Inputs**, not placeholders: `syslog_server`, `ntp_server` (IPv4), `ntp_key_id` (1–65535), `ntp_key`
  (8–32 of `[A-Za-z0-9._+=@%-]`), `management_subnet` (IPv4 CIDR, never `/0`). Validated at the API (422); the only
  caller data ever written, and only into fixed templates. A recipe missing one is `needs_input`, never verified.
  `10.0.0.100`, `10.0.0.50`, `$9$…`, `Internal_Subnet` and the like are gone.
- **No safe change → `manual_review`**: weak stored passwords (a hash cannot be derived offline), AAA when no local
  account has a strong secret (lockout), any-to-any ACL / policy (needs operator intent).
- **Engine** `app/remediation/engine.py`: `remediate_control(text, control, inputs)` and `remediate_all` (every
  failing control in catalog order, each step verified against the previous text). Gates, in order: vendor confirmed
  (`vendor_unverified`), a FAIL with decisive assurance (`provisional` / `not_failing`), a recipe (`no_recipe`),
  inputs (`needs_input`), safety (`manual_review`). The output is rescanned exactly like an upload with AI off
  (identify_vendor + parse coverage → capture → confirmed learned mappings → facts → every control → posture):
  **fixed** only if the vendor is still confirmed, lines outside the grammar and the longest foreign run did not
  grow, the target control is PASS with decisive assurance on every scope, and no other control regressed (PASS →
  not PASS, or a new / additional FAIL). Otherwise `verification_failed` with the failed checks, the generated
  output kept for review. Each outcome carries control, vendor, scopes, cited evidence (before), diff (proposed
  change), generated config (after), checks, and posture / coverage before and after (scoring v2).
- **Idempotent** by construction: recipes run only on decisive FAILs, so a fixed config yields no change.
- **API**: `POST /api/remediate` (one control; `inputs`; returns status, reason, evidence, diff, checks,
  before/after, `fixed_config`), `POST /api/remediation/plan` (every device and failing control; per-device combined
  output), `POST /api/download-fixed` (verified changes only; `inputs`; 409 when no confirmed vendor, 400 when
  nothing verified). `POST /api/verify` (applied client command text) is **removed**: no request field carries
  commands. The routes gate on the stored scan too: a control whose stored verdict is provisional (heuristic, or
  an AI proposal) is never changed, even where the fresh parser rescan could decide it.
- **Compatibility**: `generate_remediation` / `apply_remediation` remain as deprecated shims over the engine (the
  repository's `verify_fix.py` and `backend/diagnose_remediation.py` import them). `apply_remediation` ignores the
  command text it is given.
- **Frontend**: Remediation page runs the plan and separates **Fixed** / **Proposed** (needs input, with an input
  form) / **Requires human review** (manual review, verification failed, provisional) / **Unable to remediate** /
  **Unverified vendor**; each row expands to cited evidence, diff, rescan checks and before/after posture +
  coverage; download is enabled only for verified output. The finding drawer shows the same detail; provisional
  and unverified-vendor findings offer no remediation. The command-text "Verify Fix" flow is gone.
- **Tests** `tests/test_remediation_e2e.py` (rewritten, 69): Cisco and FortiGate plans (exact statuses), single
  control with scope / evidence / diff / checks / before-after, missing settings inside their blocks, FortiOS NTP
  block created or extended with balanced nesting, existing NTP servers keyed without duplicates, already-fixed
  configs untouched, every confirmed sample (30) verified + idempotent + no placeholder, per-control idempotence,
  byte-exact "only the failing settings changed" (Cisco with banner text and comments, FortiGate with config-version
  comments), CRLF, needs-input, 7 invalid inputs, malformed output kept and failed (vendor lost), no-fix and
  regression detected, unknown / Palo Alto / look-alike / mixed configs blocked, heuristic FAIL blocked, API scan →
  plan → download → real rescan equal to the plan's after posture / coverage / critical-unassessed, FortiGate
  download rescans confirmed, inputs 422 and extra command fields ignored, `/verify` gone, unknown vendor
  `vendor_unverified` + download 409, stored AI proposal blocks remediation on a confirmed vendor.
- **Deliberate test updates**: the old "every sample remediates to 100 / 0 findings" expectations were only reachable
  with placeholder secrets and invented address objects. `test_download_fixed` (HTTP fix is `no ip http server`),
  `test_phase1_honest_unknowns` (`/verify` gone; `/remediate` returns `vendor_unverified`), `test_phase2_controls`
  (remediation keys = recipe controls), `test_adaptive_api_integration` G2 (shims ignore command text),
  `test_phase3_e2e` round trip (rescan leaves exactly MGMT-005, MGMT-008, BOUNDARY-001).

Known limits:

- Remediation coverage is the recipe table: only Cisco IOS and FortiGate, only these 15 controls.
- MGMT-003 on FortiGate removes management services from WAN interfaces; MGMT-001 Cisco sets `transport input ssh`
  on every VTY range. Both carry lockout warnings; the rescan cannot know whether SSH keys exist on the device.
- The plan fixes in catalog order and does not revisit a control a later step could have made fixable.
- A generated configuration holds the NTP key the operator typed; it is returned to the caller, never persisted.

---

# Phase 9 -Framework Views + Final Demo

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

(As built, step 6 shows NIST SP 800-53 Rev. 5 and the confirmed vendor's CIS benchmark; the script actually used is
`docs/demo.md`.)

## Status: done

Suite after Phase 9: **834 passed, 2 skipped** (frontend 19 passed, build OK). Phase 0 snapshots unchanged.

- **Framework views** `app/controls/frameworks.py`, `frameworks[]` on every scan response: the scan's control
  results regrouped per (framework, version) and requirement -nothing re-evaluated. Requirement FAIL if a mapped
  control FAILs decisively; PASS only if every applicable mapped control PASSes decisively; PARTIAL; NOT_CONFIGURED
  if all mapped controls are; else UNKNOWN; N/A if all N/A. Heuristic / AI verdicts set `provisional` and never make
  a requirement PASS or FAIL. Coverage = decided ÷ applicable requirements. Each mapped control carries status,
  assurance, proposed status, decisive flag, reason and evidence.
- **Task 2** ("not assessable from configuration"): every catalog mapping is a device-configuration requirement, so
  no listed requirement needs the label; unmapped requirements are not listed, and the UI says the view is not a
  certification. **Task 3**: CIS items stay attached only to their confirmed vendor. ISO/IEC 27001:2022, DISA NDM SRG
  and CIS Controls v8 are **not implemented** -no mapping was verified and unverified mappings would inflate coverage.
- **Task 4 (remove the legacy `score`) -deliberately not done.** It stays in the API, marked deprecated, and the UI no
  longer shows it (history uses posture / coverage). `backend/test_api.py` reads `score` and
  `backend/diagnose_remediation.py` imports `calculate_score`; both are pre-existing repository scripts left untouched.
- **Persistence audit**:
  | Item | Finding |
  |---|---|
  | Recognizers | SQLite `learned_mappings` at `ADAPTIVE_DB_PATH`, loaded fresh on every scan → survive restart; a new process reuses them (test runs two real processes) |
  | AI cache | SQLite `ai_judge_cache`, intentional (Phase 7): verified answers to redacted prompts, re-verified on hit |
  | Scan history | backend: in memory only; frontend: `localStorage` |
  | Raw configurations | never written to disk (`upload_dir` is created but unused) or to SQLite |
  | **Fixed** | a provisional line `syslog host … key <secret>` could be confirmed as a recognizer or rejected, storing the key in `learned_mappings` / `rejected_lines`. Mappings and recognizers whose text holds a secret are now refused; rejected lines are stored redacted and matched via `rejection_key` (redacted, normalized) |
  | **Fixed** | the browser history stored the full scan result (findings evidence, e.g. `enable password 7 …`). It now stores summaries only and strips old entries on read |
- **Frontend**: Overview gains the per-device **Analysis Path** (vendor detection → dedicated parser or generic
  tokenizer → controls decided → AI calls / cache hits → provisional → confirmed recognizers → remediation
  available / blocked) with an explicit generic-analysis notice for unknown / unverified vendors; **Frameworks** page;
  "Review & Recognizers" navigation; history reopens scans through `GET /api/scan/{id}` and explains when the backend
  no longer holds them; loading steps name the real pipeline.
- **Tests** `tests/test_phase9_frameworks_persistence.py` (7): framework requirements equal the catalog's NIST ids and
  carry the scanned statuses; AC-17(2) FAIL with parser evidence; CIS only for the confirmed vendor; PASS needs every
  mapped control decisive and an AI proposal turns it PARTIAL + provisional; unknown vendor → NIST only, coverage 0,
  never PASS / FAIL; multi-device CIS scoping; rejected secret line stored redacted and still matched; secret line
  never becomes a recognizer; recognizer saved in one process, reused decisively (confirmed FAIL [70, 71], zero AI
  calls, coverage > 0) by a second process, with no raw configuration line persisted. Frontend:
  `FrameworkView.test.jsx`, `utils/history.test.js`.
- **Real-world matrix** (API in-process, AI off unless stated, AI transport mocked and every prompt captured):

  | Config | Vendor | Posture / coverage | Result |
  |---|---|---|---|
  | Cisco vulnerable | confirmed | 0 / 100 | 15 decisive FAILs; plan: 9 fixed, 3 needs input, 3 human review |
  | Cisco secure | confirmed | 100 / 100 | nothing to fix (download 400) |
  | FortiGate vulnerable | confirmed | 4 / 82, MGMT-005 not assessed | 9 fixed, 2 needs input, BOUNDARY-001 review |
  | FortiGate secure | confirmed | 100 / 83, MGMT-005 not assessed | nothing to fix |
  | `sample/unknown.cfg` | unknown | -/ 0 | 6 provisional; NIST view only; remediation `vendor_unverified`, download 409 |
  | `sample/paloalto.cfg` | unknown | -/ 0 | 4 provisional (suspected Telnet / HTTP FAIL); remediation blocked |
  | Synthetic Junos | unknown | -/ 0 | 1 provisional; nothing decisive |
  | Arista EOS look-alike | unverified (33 % grammar) | -/ 0 | nothing decisive, blocked |
  | Mixed IOS + foreign block | unverified (9 foreign statements) | -/ 0 | provisional only, blocked |
  | Remediation (Cisco, inputs) | confirmed | 0 → 72 on real rescan (= plan) | 12 fixed; remaining FAILs = MGMT-005, MGMT-008, BOUNDARY-001 |
  | Confirmed recognizer | unknown | -/ 0 → 11 | MGMT-001 confirmed FAIL [70, 71]; AI judge asked only MGMT-003 / MGMT-006 (line 71 appears only as scope context) |
  | Unfamiliar syntax (AI on) | unknown | -/ 0 | `lock-after 10 minutes` → MGMT-006 UNKNOWN, AI proposes PASS; no finding, no posture |
  | Fake secrets (AI on) | unknown | -/ 0 | 1 judge call; none of 6 fake secrets in the prompt |

Known limits:

- Framework views cover NIST SP 800-53 Rev. 5 and verified CIS items only.
- A line holding a secret cannot become a recognizer, so such a setting stays provisional on unknown vendors.
- Replay and `GET /api/scan/{id}` only reach scans held by the running backend.
- Pre-existing rejected lines in an existing database keep their old unredacted keys (the audited local database was
  empty).

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

- [x] Cisco/FortiGate FAIL findings unchanged from Phase 0 snapshots
- [x] No raw secret ever reaches the AI (for every secret syntax the pattern-based redactor knows)
- [x] Every control runs on every config
- [x] Every result has status, reason and evidence lines; decided results carry assurance
- [x] No PASS without evidence or a documented default; no FAIL from missing data on unknown vendors
- [x] Posture and coverage shown; unassessed never scores as passed
- [x] `sample/unknown.cfg` gives useful cited results with AI off
- [x] Admin confirmation makes the next scan decisive with zero AI calls -including after a backend restart
- [x] AI calls per config bounded by a budget and cached
- [x] Verified remediation includes a regression check
- [x] Full backend test suite green at every phase
