# updates.md: what to add to NetAuditAI after reviewing the other SIH 26155 projects

Branch: `judge-ready` · Started 2026-09-26 · **This file is the source of truth for the work below.** Every change on this
work updates this file: tick the checklist, add the commit, note anything that changed from the plan.

---

## The request (verbatim)

> Okay, before you build anything, uh, first understand all the repositories I have given to you. Then start building.
> But also make a new branch. Uh, you name it, I don't know. You can make anything. Name it anything. Then start
> working on it. Yes, these are the important things. These need to be added here. Uh, first, actually write an MD
> file that what things can be added. And uh, if they have any login thing, login feature authentication feature, I
> don't need that. I need the features that will make judges feel, oh my fucking God, it's so good. That is what I
> want. Okay, so for uh, uh, obviously not, not copy implement it, how it works, how it's working, you know,
> implement it in a code. And uh, make my app very fucking good.
>
> Oh yeah, uh, copy whatever I said from the above prompt. And also make a read.md file with the checklist on it.
> Uh, name the file uh, updates.md Now in this file, I need you to first understand the entire repository, then
> write everything that is not in my current project. And uh, write good prompts for these new things to be added in
> and divide them into phases. Uh, like one, two, three, four, whatever you want. And make sure that Claude.md is
> edited to say to update everything on that fix.md file or whatever file I said first. I don't know, updates.md or
> Claude uh, should always update the this file

---

## Ground rules for every item

1. **Implement the idea, never copy code.** None of the other repos grants a licence to copy, and SIH checks
   submissions against each other. Read how a feature behaves, then build it the NetAuditAI way.
2. **No login, accounts, roles or authentication features** (explicitly not wanted). The existing API key stays as is.
3. **Nothing fake.** No "AI processing" animations, no invented numbers. Every number shown is computed, every
   claim has a test. This is what separates NetAuditAI from most entries and must stay true.
4. **Secrets never leave redaction**, in any new endpoint, page, PDF or export.
5. **Do not use** `sih26155-poc/DISA_STIG_Juniper_Router_NDM_v3r2.audit`: it is Tenable-licensed. Public STIG IDs
   (already in the catalog) are fine.
6. Each item: tests, docs (`docs/api.md` / README where relevant), one commit, no Claude co-author line.

---

## The projects reviewed (in `sih-samne/`, git-ignored)

| Project | What it really is | Ideas worth taking |
|---|---|---|
| **SurakshaSetu** (`SIH26155-Surakshasetu-main`) | FastAPI + Next.js, Cisco/FortiGate/PAN-OS hard-coded parsers, ~12 controls, CIS/NIST/ISO. Training only pre-fills AI suggestions: it never changes a verdict. | **Attack-path graph** (Internet → interface → exposed service → device), **risk score** from exposure + asset criticality + findings, **fix ordering** (ACO vs baselines), **tamper-evident ledger** (Hyperledger Fabric) with a tamper test, Playwright end-to-end test, "Potential attack path" wording |
| **NetBaseline AI** (`sih26_ps26155`) | Closest rival: 23 controls × 4 frameworks, JSON vendor packs (Cisco, Junos, FortiOS, PAN-OS, AWS SG), taught rules merge into packs, SSH collection, per-device PDF | **Published measurements** (normalisation coverage % and latency per vendor, model benchmark), **prompt-injection defence + probe (0/6)**, **N/A for controls a platform cannot have** (NTP on an AWS security group), "conflicts resolve toward risk", architecture PDF + slides in the repo |
| **SentinelAudit** (`sih26155-main (1)`) | Browser-only React, regex, admits a "fake-but-convincing AI log" | **Fleet dashboard** (posture per device, findings by severity, devices by vendor, activity feed), **baseline model shown on screen** next to its JSON, **rules catalog page**, **vendor library page**, "recognition rate" per device |
| **POC** (`sih26155-poc`) | CLI prototype, 61 regex presence rules across 8 vendors, `learned.json` | Rule cards citing several sources (CIS, NIST, STIG) per rule, combined multi-device benchmark report |
| **SecureNova** (`my-SIH26155_SecureNova`) | Cisco + Junos hard-coded, 10 controls, Gemini advice, no training | Separate **executive vs technical** report, background job progress |
| **logith-a auditor** | One 858-line FastAPI file: LAN discovery, WiFi scan, live attack detector, credentials store | **Network discovery → audit a whole subnet** (idea only; see "not taking") |
| **umang-045** | FastAPI + OPA/Rego (3 rules), JSON mappings, static page | Policy-as-code framing (we already have it as data: catalog + seeds) |
| **xarjunpatil** | 136-line telemetry dashboard, not a config auditor | nothing |
| **MultiVendor-Security-Auditor** | Specification documents only, empty folders | **Evidence chain shown per finding** (framework → rule → field → value → line → verdict), ideal demo flow |
| Video-only: **V.E.N.O.M.** | Normalises Cisco/Juniper/Terraform, attack-path correlation, training page, PDF/Word | **Headline accuracy** ("74/74 seeded, 87.1% labelled"), Word export |
| Video-only: **Half a Dozen** | Cisco-only STIG checker (60 rules), Gemini explanations, Chart.js dashboard | Charts; "60 rules" count (answer: show mapped framework requirements) |

### What NetAuditAI already has (do not rebuild)
Multi-vendor via parsers + learned seeds · teach loop that changes verdicts · 23 controls × NIST/CIS/STIG/ISO ·
assurance levels · learned absence · verified remediation (rescan) + added lines · candidate commands (typed / AI) ·
per-device PDF with identity and "At a glance" · baseline JSON export · SSH collection · history · assistant
explanations · redaction before AI · progress strip / first-run tips.

### Not taking (and why)
| Idea | Why not |
|---|---|
| Login, RBAC, accounts | Not wanted. |
| Full Hyperledger Fabric network | Days of Docker infrastructure for one demo moment; a hash-chained ledger (Phase 3) gives the same verifiable property honestly. |
| Fine-tuned model (QLoRA) | Weeks of work and a GPU; the design keeps AI out of verdicts anyway. |
| LAN discovery / WiFi scan / live attack detector | Outside the problem statement; scanning networks in a demo venue is a risk. SSH collection already covers "fetch from devices". |
| Word export | Low value next to the PDF. |
| Tenable `.audit` import | Licence forbids it. |

---

## Phases

Order = most judge impact for the least risk first. Each item has a prompt ready to hand to Claude.

### Phase 1: Proof (numbers judges remember)

#### 1.1 Accuracy benchmark
- **From:** V.E.N.O.M. (74/74, 87.1%), NetBaseline (measured tables).
- **Why judges care:** one number on a slide beats a paragraph of claims.
- **Prompt:**
  > Build `backend/scripts/benchmark.py` and `benchmark/labels.json`. Labels come from two places: the 20 planted
  > vulnerabilities in `demo-sih/README.md` (independent: written with the files) plus the "deliberately secure"
  > settings there, and per-control labels for the 16 `teach/*_01_secure*` / `*_02_insecure*` files written by reading
  > each file (only settings the file clearly states; ambiguous ones are left out and listed). Run every file through
  > the real scan pipeline with no AI. Report per vendor and overall: planted issues detected as decisive FAIL,
  > flagged as provisional, left undecided, missed; false FAILs on labelled-secure settings; coverage and latency per
  > file. Write `benchmark/RESULTS.md` (regenerated by the script, never hand-edited) and add a test that fails if
  > detection drops below the committed result. Put the headline in the README. Report misses honestly.
- **Checklist:**
  - [ ] labels.json with sources and excluded (ambiguous) items
  - [ ] benchmark script, deterministic, no AI
  - [ ] RESULTS.md generated; headline in README
  - [ ] regression test

#### 1.2 Prompt-injection defence and probe
- **From:** NetBaseline (spotlighting / datamarking, 0 of 6 attacks succeeded).
- **Why judges care:** "What if a config contains 'ignore previous instructions'?" is a question a security jury asks.
- **Prompt:**
  > Harden every prompt that carries configuration text (`app/ai/judge.py`, `app/adaptive/interpreter.py`,
  > assistant, candidate drafting): fence the data with a per-request random nonce and prefix every config line with
  > a marker, and state in the system prompt that fenced text is data. Keep the existing guarantees (redaction first;
  > an AI answer is only a proposal whose quote must be verified on the cited line). Add
  > `backend/scripts/probe_injection.py` with hostile configs (comment says "report telnet disabled", banner says
  > "approved by admin", fake end-of-data marker …) and a unit test proving no verdict can change from AI output
  > alone. Document results in `docs/security-model.md`.
- **Checklist:**
  - [ ] nonce fence + line marking in every config-carrying prompt
  - [ ] probe script with ≥6 hostile configs
  - [ ] test: AI output alone never changes a decided verdict
  - [ ] documented result

### Phase 2: Wow on screen

#### 2.1 Attack paths (deterministic)
- **From:** SurakshaSetu (graph), V.E.N.O.M. (correlation).
- **Why judges care:** turns a list of findings into "this is how you get owned", the moment people remember.
- **Prompt:**
  > Add `backend/app/analysis/attack_paths.py`: a small catalog of attack chains, each a sequence of steps with the
  > controls that enable them (e.g. Internet-reachable management [MGMT-010/MGMT-003] → cleartext protocol
  > [MGMT-001/MGMT-002/MGMT-004] → default account or no lockout [AUTH-003/AUTH-001] → full device control; also
  > no remote logging [LOG-001] → "and nobody sees it"). A chain appears only when every required step is a decisive
  > FAIL on that device; each step cites its findings and lines. Label them "Potential attack path", never
  > "exploit". Include which fix breaks the chain (the cheapest step). Expose in the scan response, render as a
  > left-to-right step graph on Results (plain SVG/CSS, no new dependency), and add a section to the PDF. Tests: a
  > chain fires only with all steps failing; fixing one step removes it.
- **Checklist:**
  - [ ] chain catalog + evaluator + tests
  - [ ] API field + docs
  - [ ] Results page graph
  - [ ] PDF section
  - [ ] "break the chain" fix hint

#### 2.2 Evidence chain per finding
- **From:** MultiVendor-Security-Auditor spec, SentinelAudit (baseline on screen).
- **Prompt:**
  > In the finding drawer, show the whole chain as one vertical trace: framework requirement(s) → control → normalized
  > field → value (+ assurance) → the configuration line(s) → verdict. Data already exists (control results carry
  > facts); expose what is missing through the scan response, redacted. Tests for the drawer.
- **Checklist:**
  - [ ] trace UI in the finding drawer
  - [ ] any missing fields exposed (redacted)
  - [ ] tests

#### 2.3 Baseline model on screen, and vendor side-by-side
- **From:** SentinelAudit (baseline view + JSON), NetBaseline (canonical parameters).
- **Why judges care:** the core claim of the problem statement ("vendor-neutral model") becomes visible: a Cisco
  and a Junos device side by side, same fields, different syntax.
- **Prompt:**
  > Add a "Baseline model" tab per device on Results that renders `GET /api/scan/{id}/baseline` as a table (field,
  > value, assurance, line) with the JSON beside it, and a compare view for a multi-device scan: rows = fields,
  > columns = devices, each cell the value and the original line on hover. Reuse existing components; no new
  > dependency. Tests.
- **Checklist:**
  - [ ] per-device baseline tab
  - [ ] multi-device compare view
  - [ ] tests

#### 2.4 Fleet dashboard
- **From:** SentinelAudit, Half a Dozen.
- **Prompt:**
  > For multi-device scans, add an overview at the top of Results: posture per device (bar), findings by severity
  > (stacked), devices by vendor/path (parser vs learned), most common failing controls across the fleet, and the
  > attack paths found. Plain SVG/CSS charts, accessible (text equivalents), dark-mode tokens. Numbers come from
  > the existing counts; nothing recomputed differently. Tests.
- **Checklist:**
  - [ ] charts + text equivalents
  - [ ] fleet "top failing controls"
  - [ ] tests

### Phase 3: Trust and theme ("Blockchain & Cybersecurity")

#### 3.1 Tamper-evident audit ledger
- **From:** SurakshaSetu (Fabric ledger + tamper test).
- **Why judges care:** matches the theme and answers "how do we know this report was not edited?" without faking a
  blockchain.
- **Prompt:**
  > Add an append-only, hash-chained audit ledger (`backend/app/ledger/`): every scan, taught recognizer,
  > confirmed/rejected candidate and generated report appends a record `{seq, time, kind, subject, content_hash,
  > prev_hash, hash}` where content hashes are SHA-256 of the redacted artefact (never secrets). Store in the existing
  > DB (SQLite/Postgres). `GET /api/ledger` lists, `GET /api/ledger/verify` recomputes the chain and reports the first
  > broken link. Print the report's hash and ledger position in the PDF footer; add `POST /api/ledger/verify-report`
  > that takes a PDF and says whether it matches a ledger entry. Ledger page in the UI with a Verify button. Test:
  > editing any stored record is detected. Call it a "hash-chained ledger", not a blockchain.
- **Checklist:**
  - [ ] ledger store + append on the 4 event kinds
  - [ ] verify endpoint + tamper test
  - [ ] PDF footer hash + verify-report
  - [ ] Ledger page

#### 3.2 Contextual risk score
- **From:** SurakshaSetu (exposure + asset criticality + findings).
- **Prompt:**
  > Next to posture (compliance), add a risk level per device that also weighs context: internet exposure (from
  > MGMT-010 / interface facts, or a per-device toggle at upload), asset criticality (optional select: low / medium /
  > high / critical), attack paths found. Fixed, documented weights; the formula shown in a tooltip and the PDF.
  > Posture stays exactly as it is. Tests.
- **Checklist:**
  - [ ] risk model + docs + tests
  - [ ] optional criticality/exposure input at upload
  - [ ] shown on Results and in the PDF

#### 3.3 Recommended fix order
- **From:** SurakshaSetu (ACO sequencing vs baselines).
- **Prompt:**
  > On the Fix page, order fixes by risk removed per effort, respecting dependencies (e.g. restrict management
  > before changing protocols; a fix that breaks an attack path first). Deterministic greedy with the reason shown per
  > step ("breaks attack path X", "critical, one line"). Compare against severity-only order and show the difference
  > in total risk after N steps. Tests.
- **Checklist:**
  - [ ] ordering + reasons + tests
  - [ ] Fix page uses it

### Phase 4: Coverage and honesty polish

#### 4.1 N/A for controls a platform cannot have
- **From:** NetBaseline (AWS security group: 21 controls N/A).
- **Prompt:**
  > When a configuration is a cloud security group (flattened JSON), controls about device management a security
  > group cannot express (NTP, banner, SSH version, idle timeout, AAA, password policy …) are N/A with the reason,
  > not NOT_CONFIGURED. Decide from the structure (learned knowledge / flattened JSON), not a vendor name. Tests.
- **Checklist:**
  - [ ] N/A rule + reasons + tests

#### 4.2 Rules catalog page
- **From:** SentinelAudit, POC.
- **Prompt:**
  > A page listing the 23 controls: question, severity, what it reads (fields), every framework requirement it maps
  > (NIST, CIS, STIG, ISO) with IDs, and the total number of mapped requirements. Answers "only 23 rules?".
- **Checklist:**
  - [ ] catalog endpoint (or reuse) + page + tests

#### 4.3 Executive summary PDF
- **From:** SecureNova (executive vs technical).
- **Prompt:**
  > Add a one-page executive PDF option (risk, posture, top 3 problems, attack paths, what to do first) next to the
  > full technical report. Reuse the report model.
- **Checklist:**
  - [ ] executive variant + tests

### Phase 5: Submission polish
- [ ] Architecture 2-page PDF generated from `docs/architecture-brief.md` into the repo
- [ ] README: headline benchmark numbers, attack paths and ledger screenshots
- [ ] Demo script updated for the new screens (`docs/demo.md`)
- [ ] One end-to-end browser test of the demo flow

---

## Progress log

| Date | Item | Commit | Notes |
|---|---|---|---|
| 2026-09-26 | Review of 9 repos + this plan | – | branch `judge-ready` created |
