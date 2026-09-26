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
  - [x] labels.json with sources and excluded (ambiguous) items
  - [x] benchmark script, deterministic, no AI
  - [x] RESULTS.md generated; headline in README
  - [x] regression test

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
  - [x] nonce fence + line marking in every config-carrying prompt
  - [x] probe script with ≥6 hostile configs
  - [x] test: AI output alone never changes a decided verdict
  - [x] documented result

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
  - [x] chain catalog + evaluator + tests
  - [x] API field + docs
  - [x] Results page graph
  - [x] PDF section
  - [x] "break the chain" fix hint

#### 2.2 Evidence chain per finding
- **From:** MultiVendor-Security-Auditor spec, SentinelAudit (baseline on screen).
- **Prompt:**
  > In the finding drawer, show the whole chain as one vertical trace: framework requirement(s) → control → normalized
  > field → value (+ assurance) → the configuration line(s) → verdict. Data already exists (control results carry
  > facts); expose what is missing through the scan response, redacted. Tests for the drawer.
- **Checklist:**
  - [x] trace UI in the finding drawer
  - [x] any missing fields exposed (redacted)
  - [x] tests

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
  - [x] per-device baseline tab
  - [x] multi-device compare view
  - [x] tests

#### 2.4 Fleet dashboard
- **From:** SentinelAudit, Half a Dozen.
- **Prompt:**
  > For multi-device scans, add an overview at the top of Results: posture per device (bar), findings by severity
  > (stacked), devices by vendor/path (parser vs learned), most common failing controls across the fleet, and the
  > attack paths found. Plain SVG/CSS charts, accessible (text equivalents), dark-mode tokens. Numbers come from
  > the existing counts; nothing recomputed differently. Tests.
- **Checklist:**
  - [x] charts + text equivalents
  - [x] fleet "top failing controls"
  - [x] tests

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
  - [x] ledger store + append on the 4 event kinds
  - [x] verify endpoint + tamper test
  - [x] PDF footer hash + verify-report
  - [x] Ledger page

#### 3.2 Contextual risk score
- **From:** SurakshaSetu (exposure + asset criticality + findings).
- **Prompt:**
  > Next to posture (compliance), add a risk level per device that also weighs context: internet exposure (from
  > MGMT-010 / interface facts, or a per-device toggle at upload), asset criticality (optional select: low / medium /
  > high / critical), attack paths found. Fixed, documented weights; the formula shown in a tooltip and the PDF.
  > Posture stays exactly as it is. Tests.
- **Checklist:**
  - [x] risk model + docs + tests
  - [x] optional criticality/exposure input at upload
  - [x] shown on Results and in the PDF

#### 3.3 Recommended fix order
- **From:** SurakshaSetu (ACO sequencing vs baselines).
- **Prompt:**
  > On the Fix page, order fixes by risk removed per effort, respecting dependencies (e.g. restrict management
  > before changing protocols; a fix that breaks an attack path first). Deterministic greedy with the reason shown per
  > step ("breaks attack path X", "critical, one line"). Compare against severity-only order and show the difference
  > in total risk after N steps. Tests.
- **Checklist:**
  - [x] ordering + reasons + tests
  - [x] Fix page uses it

### Phase 4: Coverage and honesty polish

#### 4.1 N/A for controls a platform cannot have
- **From:** NetBaseline (AWS security group: 21 controls N/A).
- **Prompt:**
  > When a configuration is a cloud security group (flattened JSON), controls about device management a security
  > group cannot express (NTP, banner, SSH version, idle timeout, AAA, password policy …) are N/A with the reason,
  > not NOT_CONFIGURED. Decide from the structure (learned knowledge / flattened JSON), not a vendor name. Tests.
- **Checklist:**
  - [x] N/A rule + reasons + tests

#### 4.2 Rules catalog page
- **From:** SentinelAudit, POC.
- **Prompt:**
  > A page listing the 23 controls: question, severity, what it reads (fields), every framework requirement it maps
  > (NIST, CIS, STIG, ISO) with IDs, and the total number of mapped requirements. Answers "only 23 rules?".
- **Checklist:**
  - [x] catalog endpoint (or reuse) + page + tests

#### 4.3 Executive summary PDF
- **From:** SecureNova (executive vs technical).
- **Prompt:**
  > Add a one-page executive PDF option (risk, posture, top 3 problems, attack paths, what to do first) next to the
  > full technical report. Reuse the report model.
- **Checklist:**
  - [x] executive variant + tests

### Phase 5: Submission polish
- [ ] Architecture 2-page PDF generated from `docs/architecture-brief.md` into the repo
- [x] README: headline benchmark numbers, attack paths and ledger screenshots
- [x] Demo script updated for the new screens (`docs/demo.md`)
- [x] One end-to-end browser test of the demo flow

### Phase 6: Beyond the other projects
Asked for on 2026-09-27 ("start working on the 5 things you said"). None of the reviewed projects has these; they
build on what NetAuditAI already keeps. Branch `phase-6`.

#### 6.1 Changes since the last audit (drift)
- **Why judges care:** an audit becomes monitoring: what got fixed, what newly broke, on the same device.
- **Prompt:**
  > Compare a scan with the most recent earlier archived scan of the same device (hostname + vendor) using only the
  > redacted responses already in the `scans` table; no configuration is stored. Per device: posture and risk
  > before → after, checks fixed (decided FAIL → decided PASS), new problems (→ decided FAIL), checks no longer
  > decided (FAIL → undecided, never called fixed), attack paths closed/opened. Endpoint + a section on Results.
- **Checklist:**
  - [x] drift model + tests
  - [x] endpoint + docs
  - [x] Results section + test

#### 6.2 Offline AI (local model)
- **Why judges care:** government networks are often air-gapped; "does it need the internet?" gets a "no".
- **Prompt:**
  > Let the AI layer use a local OpenAI-compatible server (Ollama, llama.cpp) chosen by configuration instead of
  > Groq. Same redaction and fence; same prompts. Status endpoint says which provider is active. No new dependency
  > if the current client can target another base URL.
- **Checklist:**
  - [x] provider setting + tests
  - [x] status shows provider; docs

#### 6.3 Checks across devices
- **Why judges care:** problems one-device tools cannot see.
- **Prompt:**
  > For a scan with several devices, add fleet findings from the facts already read: the same SNMP community or
  > password hash on several devices (compared by hash, never shown), devices disagreeing on NTP / syslog servers,
  > a setting every other device has but one is missing. Each cites the devices and lines. Shown in the Fleet view.
- **Checklist:**
  - [x] cross-device checks + tests
  - [x] API field + Fleet view + docs

#### 6.4 Command line for CI pipelines
- **Why judges care:** configs are checked before they reach devices, like code.
- **Prompt:**
  > `python -m app.cli scan <files or dir> [--framework] [--fail-on high] [--sarif out.sarif] [--json]`, using the
  > same engine without the web server. Exit code 1 when a decided FAIL at or above the threshold exists. SARIF so
  > GitHub shows findings on the lines. Example workflow in docs.
- **Checklist:**
  - [x] CLI + exit codes + tests
  - [x] SARIF output + test
  - [x] docs + example workflow

#### 6.5 Organisation baseline
- **Why judges care:** auditors ask for "our policy", not only NIST's.
- **Prompt:**
  > A small policy file (JSON) that tightens thresholds (e.g. session timeout ≤ 10 min, minimum password length)
  > and lists approved NTP / syslog / AAA servers. Checks read the policy; results say when the organisation's value
  > was used instead of the default. Upload page accepts it optionally; CLI takes `--policy`.
- **Checklist:**
  - [x] policy model + validation + tests
  - [x] checks use it; results cite it
  - [x] upload + CLI option; docs

---

## Progress log

| Date | Item | Commit | Notes |
|---|---|---|---|
| 2026-09-26 | Review of 9 repos + this plan | 134fd0a | branch `judge-ready` created |
| 2026-09-26 | 1.1 Accuracy benchmark | (this commit) | Planted 17/20 decided + 2 suspected + 1 undecided, fixtures 70/87, **0 missed, 0 false alarms**. The first run found 1 real miss (EXOS `configure syslog delete …` read as a syslog server): the tokenizer now treats `configure <feature> delete/remove` as a removal. SNMP community seeds added from teach/ syntax (Arista `ro access`, Check Point, Aruba, EXOS): fixtures 60 → 70. Two EXOS `readonly/readwrite <name>` seeds dropped: the secret gate refuses them. |
| 2026-09-26 | 1.2 Prompt-injection defence | (this commit) | Fence tag is a hash of the fenced lines instead of a random nonce: unforgeable and deterministic, so the judge cache and the interpreter's determinism test still hold. Live probe 0/6; honest note that 4 of 6 hit already-decided checks the AI never sees. |
| 2026-09-26 | 2.1 Attack paths | (this commit) | 4 chains (remote takeover, password guessing, SNMP exposure, perimeter bypass), each step any-of decided FAILs. Built from the already-redacted results. Plain CSS flow (arrows; stacks on phones), no new dependency. Cisco demo: takeover + perimeter; PAN-OS demo: 3 paths. |
| 2026-09-27 | 2.2 Evidence chain | (this commit) | Results now carry `facts[]` and `requirements[]`; drawer shows Required by → Check → Read as (field = value, assurance, line) → Verdict. Kept behind a "Show how this was decided" toggle: the drawer's progressive-disclosure rule (lines only on request) is tested and was kept. |
| 2026-09-27 | 2.3 Baseline compare | (this commit) | "Compare the devices field by field" on Results: one column per device, every field the checks read, each value titled with its source line and assurance. Loaded on request only. Structured values spelled out (no `[object Object]`). |
| 2026-09-27 | 2.4 Fleet view | (this commit) | Per-device posture/coverage/risk and the most common failing controls across the scan, each with a text equivalent. |
| 2026-09-27 | 3.1 Tamper-evident ledger | (this commit) | Hash-chained table (migration v6, SQLite + Postgres), entries for scan, report, recognizer save, candidate confirm/reject. `/api/ledger`, `/verify`, `/verify-report`; Audit ledger page. Tamper test flips one bit (PDF streams are compressed). Note: starting the backend against a Supabase `.env` applies migration v6 to that database. |
| 2026-09-27 | 3.2 Contextual risk | (this commit) | `device_risk`: worst severity + exposure + attack paths, times criticality; bands low/medium/high/critical; reasons and formula returned. Criticality and internet-facing are optional upload fields (422 on a bad value). |
| 2026-09-27 | 3.3 Fix order | (this commit) | (severity + path bonus) / effort; top 5 on the Fix page with the reason, so the fix that breaks a critical path comes first. |
| 2026-09-27 | 4.1 Platform N/A | (this commit) | Data-driven `platform_profiles.json`; AWS security groups: 20 controls N/A, MGMT-003, MGMT-010, BOUNDARY-001 still judged. Only UNKNOWN / NOT_CONFIGURED become N/A, never a decided verdict. |
| 2026-09-27 | 4.2 Rules catalog | (this commit) | `GET /api/catalog`: 23 checks → 78 requirements (CIS 27, NIST 25, ISO 16, STIG 10); Rules catalog page. CIS mappings shown only for the matching vendor. |
| 2026-09-27 | 4.3 Executive PDF | (this commit) | `variant: executive` ordered by the most severe attack path each fix breaks; ledger note in every PDF. |
| 2026-09-27 | Browser check + Phase 5 | (this commit) | Cisco + PAN-OS scan checked in the browser: 5 paths, risk critical, 23 compared fields, ledger verifies. README accuracy/highlights and the 2-minute judge path in `docs/demo.md`. Still open: architecture PDF in the repo, end-to-end browser test. |
| 2026-09-27 | Phase 6 plan | (this commit) | 5 features added as Phase 6 on branch `phase-6`; `pytest-xdist` added earlier (`pytest -n auto`: 41 min → 9 min). |
| 2026-09-27 | 6.1 Drift | (this commit) | `GET /api/scan/{id}/drift` + "Since the last audit" on Results. Matches by hostname + vendor against the redacted scan archive (last 200 scans; `ponytail` note on the query). FAIL → undecided is its own list, never counted as fixed. |
| 2026-09-27 | 6.2 Offline AI | (this commit) | `LOCAL_AI_URL` / `LOCAL_AI_MODEL` send every AI call to a local OpenAI-compatible server. Change from the plan: the Groq SDK hard-codes its `/openai/v1` path, so a ~20-line httpx client (already installed) is used for the local server; no new dependency. Status returns `provider`; the assistant says when AI is local. Not tried against a real Ollama in this session. |
| 2026-09-27 | 6.3 Checks across devices | (this commit) | `fleet_findings`: shared SNMP community (matched by sha256, never shown), NTP and syslog server mismatches, decided facts only; shown under Fleet. Demo pair: shared `public` + NTP mismatch. Changes from the plan: password-hash reuse left out (no normalized field carries the hash); "one device missing what the others have" left out (each missing setting is already a per-device FAIL). |
| 2026-09-27 | 6.4 CLI for CI | (this commit) | `python -m app.cli scan … [--fail-on] [--sarif] [--json] [--db]`; exit 0/1/2. Runs on a throwaway seeded DB with AI off (deterministic, writes nothing to the deployment DB); the benchmark now reuses the same `isolated_engine()`. SARIF cites the first evidence line. `docs/cli.md` with a GitHub Actions workflow (not run on GitHub in this session). |
| 2026-09-27 | 6.5 Organisation policy | (this commit) | `app/controls/policy.py`: idle timeout, login attempts, password length (tighten only; looser = 422 / exit 2), approved NTP and syslog servers. Active policy is a context variable set in `run_scan` and `live_scan`, so teaching and remediation re-checks use the scan's policy without new parameters. Results cite "(organisation policy '…')"; response echoes `policy`; Upload takes a JSON file; CLI `--policy`; `docs/policy.md`. Changes from the plan: approved AAA servers left out (the AAA fact carries no server list); automatic fixes still write 5 minutes, so a policy under 5 makes that fix fail its re-check (documented). |
| 2026-09-27 | 5 End-to-end browser test | (this commit) | `frontend/e2e/demo.spec.js` (`npm run e2e`): the 2-minute judge path in a real browser against the real backend (own ports, throwaway DB, AI off). Uses the installed Chrome on Windows (`PW_CHANNEL` to change); `npx playwright install chromium` elsewhere. **It found a real bug:** a two-device executive report downloads as a .zip, which the ledger could not check, so the demo's "Genuine" step showed "Not found". `verify-report` now checks every PDF in a .zip (zip-bomb guarded; a damaged archive matches nothing) and the Ledger page accepts .zip. |
| 2026-09-27 | Fixes from demo use | (this commit) | Asked for while using the PAN-OS demo. **Attack paths** moved to their own sidebar page and redesigned (summary, card per path, step rail, fix-here highlight). **Ask AI** reports found only when it names a line the teach page can show. **Next** (rescore) appears once one command is confirmed, not only when every item is decided. **BOUNDARY-003** decides LLDP on an interface an external zone holds (zone logic shared with MGMT-010). **AUTH-002** on PAN-OS: absence decided from `data/factory_defaults.json` (reviewed factory default: complexity off); PAN-OS lockout not added, no real syntax in teach/ or Batfish. Benchmark planted 17/20 → **18/20**, still 0 missed, 0 false alarms. |
| 2026-09-27 | Docs brought up to date | (this commit) | README (highlights for drift, cross-device checks, policy, offline AI and CLI; status counts; page table with Attack paths, Next, ledger .zip), demo (Attack paths page), API (Next offered after one confirmation; ask-ai `found` only with a confirmable line), testing (new backend, frontend and e2e tests; counts; `-n auto`), roadmap (done items, known gaps: PAN-OS lockout, MGMT-010 citing one service line, teach-page wording, architecture PDF). |
| 2026-09-27 | Final sweep | (this commit) | Backend 1509 passed / 2 skipped, frontend 149, e2e 1, build OK. Browser walkthrough with a PAN-OS file the demo never used (`teach/…/paloalto_02_insecure.conf`): every page loads, no console errors, typed AAA command verified (MGMT-008 fail → pass, score 16 → 86). Fixed on the way: upload page checkbox alignment and native policy file picker, the same file chosen twice scanned twice, long hostnames broken at the hyphen on the Overview, undecided count badge (14) disagreeing with its heading (10), "Fix it for me" offered for a missing setting it can never fix, Copy button over long commands, Frameworks status label overlapping the requirement id, Devices page saying automatic fixes need a confirmed vendor. |
