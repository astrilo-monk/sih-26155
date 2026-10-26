# updates.md: the next round of work for NetAuditAI

Started 2026-09-27. **This file is the source of truth for the work below.** Every change on this work updates this
file: tick the checklist, add a row to the Progress log (date, item, commit, notes), and record any change from the
plan, in the same commit as the work.

The previous plan (Phases 1-6: benchmark, injection probe, attack paths, evidence chain, baseline compare, fleet,
ledger, risk, fix order, platform N/A, rules catalog, executive PDF, drift, offline AI, cross-device checks, CLI,
policy) is finished and lives in git: `git show 0618e5e:updates.md`. Its one open item (architecture PDF) is carried
over as 0.2.

---

## Status (2026-09-28)

All work is on branch **`final-updates`** (not merged into `main`, not pushed). `updates.md` itself is
git-ignored, so it is in no commit.

### Done

| Item | What it delivered | Commit |
|---|---|---|
| 0.1 One set of numbers | Every count in README and docs matches a fresh run | `9603c9a` |
| 0.2 Architecture PDF | `docs/architecture-brief.pdf` (2 pages) from `backend/scripts/build_architecture_pdf.py` | `9603c9a` |
| 1.1 Brace-block Junos | Set-style seeds also read brace files, at the leaf's own line; `/* */` and `inactive:` handled | `9603c9a` |
| 1.2 MikroTik | Default SNMP community and plaintext user passwords read; a custom community name no longer leaks into the scan response | `9603c9a` |
| 1.3 Terraform | `.tf` read for AWS, Azure, GCP rules, cited at the rule's own line; device-only checks N/A; variables never decide | `9603c9a` |
| 1.4 Azure NSG / GCP JSON | Both CLI exports read; JSON flattening fixed (GCP ports kept with their source, `denied` never read as a permit) | `9603c9a` |
| 2.4 Citation check | `test_citations.py`: every citation, attack-path step and posture checked independently over all benchmark and demo files | `8f6ce5f` |
| 2.3 Held-out benchmark | 9 real never-seen configs (pybatfish), labels committed first; first run 20/21, the miss was an IOS parser bug now fixed: 21/21, 0 false alarms | `738ff1d` labels, `12f7e35` results |
| 2.2 Attack-path proof | Each of the 4 chains proved on a positive config and a one-line-fix negative (IOS + seed-based Junos); recorded in `data/path_validation.json`, cited on the page and in the PDF | `5c4781a` |
| 2.1 CVE context | Committed NVD cache for 45 OS trains; stated IOS / IOS-XE / FortiOS versions show critical/high CVE counts and the top 5 on Devices and in the PDF, with the caveat; never part of a score | `6d77412` |
| 3.1 Two-minute demo | Four dialects in one scan (Cisco, PAN-OS, brace Junos, Terraform), CVE context and path proof shown; every step timed by the e2e test | `0d7b488` |
| 3.2 Five-slide deck | `docs/presentation.pptx` (git-ignored; source `docs/build_presentation.js`), every number sourced | `8918751` |
| 1.5 SONiC and Cumulus | `config_db.json` tables and NVUE commands read (SNMP, syslog, NTP, TACACS+/RADIUS), each seed with its doc link; two secret leaks fixed | `3beb003` |

Numbers now: seeds 165 → **243**; benchmark planted **18/20**, fixtures 70/87 → **89/112**, 0 missed,
0 false alarms; backend **1644** passed / 2 skipped, frontend **151**, e2e 1.

### Left

Nothing: every item of every phase is done (0 open checkboxes). A full run of every backend and frontend test, and
a check of three configurations through the website, follow below in the Progress log and in `output.md`.

---

## The request (verbatim)

> what updates are needed? create a new updates.md file and write all the work that is needed to be completed in
> phases with perfect prompt and where to find the files that needs changings and also to take useful things from
> other projects in the folder sih-samne

---

## Ground rules for every item

1. **Implement the idea, never copy code or sample files.** None of the other repos grants a licence, and SIH checks
   submissions against each other. Write our own fixtures in the same style.
2. ~~**No login, accounts, roles or authentication features.**~~ Changed 2026-10-03 at the user's request:
   optional Supabase accounts so one visitor cannot read what another taught (see Progress log). Still no roles.
3. **Nothing fake.** Every number shown is computed, every claim has a test. Absence is never a PASS.
4. **Secrets never leave redaction**, in any new endpoint, page, PDF, cache or export.
5. **Do not use** `sih26155-poc/DISA_STIG_Juniper_Router_NDM_v3r2.audit` (Tenable-licensed).
6. **Vendor-agnostic first.** The problem statement asks for no hard-coded command library. Prefer a generic
   structure step or seed knowledge (data) over a new dedicated parser (code).
7. Each item: tests, docs (`docs/api.md`, README, `docs/seed-knowledge.md` where relevant), one commit, no Claude
   co-author line. Re-run `python backend/scripts/benchmark.py` after anything that touches reading or seeds; the
   benchmark test must not get worse.

---

## Why this round: what testing against the problem statement showed (2026-09-27)

Both ways, same day: the other teams' samples through our engine (`python -m app.cli scan … --db <copy>`), and our
samples through theirs.

| Input | Result on NetAuditAI | Gap |
|---|---|---|
| Junos in **braces** (hierarchical) format, `sih26155-auditor-main/samples/sample_juniper.conf` | 6 problems. V.E.N.O.M. finds 24 with a JunOS parser. | Our 36 Junos seeds are `set`-style; braces format is barely read. |
| **Terraform** `main.tf` (AWS) | 0 lines read, no result. V.E.N.O.M.: 15 findings. | No HCL reading. The problem statement names cloud-native security groups (AWS, Azure, GCP). |
| MikroTik `demo_mikrotik.cfg` | Web and allow-all firewall decided, Telnet only suspected; **missed** `/snmp community … name=public` (line 8) and `/user set admin password=admin123` (line 9). | Basic checks a judge will try. |
| Azure NSG / GCP firewall JSON | JSON flattening exists (`backend/app/structure/structured.py`), lexicon knows `sourceAddressPrefix` / `sourceRanges`, but **no seeds** ship (only 4 AWS ones). | Named in the problem statement. |
| SONiC `config_db.json`, Cumulus | Vendor hints exist in `backend/app/adaptive/vendor.py`; **no seeds**. | Named in the problem statement ("White Box … SONiC, Cumulus"). |
| README | "Status" says 1509 backend / 149 frontend tests; "Testing" says 1227 / 119. | A judge who spots one wrong number distrusts the rest. |

Where we are already ahead (do not rebuild): automatic vendor detection, 4 frameworks (V.E.N.O.M. has CIS + 4 NIST
rules, no STIG/ISO), device-specific verified remediation, SSH collection (Netmiko/NAPALM), ledger (fits the
"Blockchain & Cybersecurity" theme), drift, policy, CLI/SARIF, injection defence.

---

## The projects in `sih-samne/` (git-ignored)

| Folder | What it is | Status of its ideas |
|---|---|---|
| `sih26155-auditor-main` (**V.E.N.O.M.**, source now available) | Flask, ~5.7k lines Python. User picks one of 3 source types (Cisco IOS, JunOS braces, Terraform AWS); unknown vendors fall back to the Cisco parser. 36 Cisco + 18 AWS YAML rules (CIS; 4 NIST). Evidence gate (score withheld below 60% recognised lines). 147 tests pass. | **New this round:** offline CVE context by OS version (2.1), positive/negative fixture proof per attack path (2.2), held-out labelled set with labels committed first (2.3), independent citation check (2.4), Terraform reading (1.3). |
| `sih26155-auditor` | Older snapshot of one team's backend/frontend (logith-a: one-file FastAPI, LAN discovery, WiFi scan) | Nothing new (discovery out of scope). |
| `SIH26155-Surakshasetu-main` | FastAPI + Next.js, attack graph, Fabric ledger, Playwright | All taken last round (attack paths, ledger, risk, fix order, e2e). Its `vendors/registry.py` lists SONiC as "not implemented"; we can beat that (1.5). |
| `sih26_ps26155` (NetBaseline AI) | JSON vendor packs; `parsers/rulepack.py` has block styles INDENT / FLAT_SET / CONFIG_END / KEY_PATH / JSON | Taken last round (measurements, injection probe, N/A). **New idea:** treat block style as data, so one flattener serves many dialects (1.1). |
| `sih26155-main (1)` (SentinelAudit) | Browser-only React | Taken (fleet, baseline on screen, rules catalog). |
| `sih26155-poc` | CLI, 61 regex rules, 8 vendors | Taken (multi-source rule cards). Licence rule 5 applies. |
| `my-SIH26155_SecureNova` | Cisco + Junos, Gemini, 4 pptx decks | Taken (executive PDF). Its decks are a reference for the 5-slide limit (3.2). |
| `sih2026-26155` (umang-045) | FastAPI + OPA/Rego, 3 rules | Nothing new. |
| `SIH26155-AI-Driven-…-Auditor` (xarjunpatil) | ~200-line telemetry dashboard | Nothing. |
| `SIH26155-MultiVendor-Security-Auditor-main (1)` | Specification only | Taken (evidence chain). |

### Not taking (and why)
| Idea | Why not |
|---|---|
| Choosing the vendor by hand (V.E.N.O.M.) | Detection is ours and better; a user cannot know every dialect. |
| Falling back to the Cisco parser for unknown vendors | Produces Cisco-default findings with no line on Arista (tested). |
| Assuming vendor defaults when a line is absent, for every vendor | Only with a reviewed `factory_defaults.json` entry, as now. |
| Word (DOCX) export, fake login pages | Low value / looks fake to a judge. |
| Dedicated Terraform or Junos parser classes | Rule 6: a generic brace flattener + seeds covers both as data. |
| Fabric network, fine-tuned model, LAN discovery | Unchanged from last round. |

---

## Phases

Order: highest judge impact for lowest risk first. Each item has a ready prompt, the files to touch, and a checklist.

### Phase 0: Credibility fixes (an hour, do first)

#### 0.1 One set of numbers everywhere (DONE)
- **Files:** `README.md` (sections "Status", "Testing", "Measured accuracy"), `docs/testing.md`, `docs/demo.md`,
  `docs/architecture-brief.md`, `benchmark/RESULTS.md` (generated, do not hand-edit).
- **Prompt:**
  > Run the full backend suite (`cd backend && venv\Scripts\python -m pytest tests -q -n auto`), the frontend suite
  > (`cd frontend && npm test`) and `python backend/scripts/benchmark.py`. Then make every count in README.md,
  > docs/testing.md, docs/demo.md and docs/architecture-brief.md match that run exactly. The README currently says
  > 1509/149 in "Status" and 1227/119 in "Testing". State each number once where possible and point to it elsewhere.
  > Grep the docs for any other stale count (tests, recognizers, dialects, requirements, controls) and fix it.
- **Checklist:**
  - [x] fresh run of both suites + benchmark
  - [x] every count in README and docs matches it
  - [x] grep shows no stale count left

#### 0.2 Architecture document as a 2-page PDF (carried over) (DONE)
- **Files:** `docs/architecture-brief.md` (source), new `docs/architecture-brief.pdf`, new
  `backend/scripts/build_architecture_pdf.py`, README "Documentation" table.
- **Prompt:**
  > The deliverables require an architecture document of at most 2 pages. Generate `docs/architecture-brief.pdf` from
  > `docs/architecture-brief.md` with ReportLab (already in `backend/requirements.txt`; reuse the styles in
  > `backend/app/reporting/report.py` where it fits). Include the pipeline diagram as drawn text or simple ReportLab
  > shapes, no new dependency. Fail the script if the output has more than 2 pages. Link the PDF from the README.
- **Checklist:**
  - [x] script + PDF ≤ 2 pages
  - [x] README link

### Phase 1: Close the problem-statement gaps found by testing

#### 1.1 Brace-block flattening (Junos hierarchical, and the base for Terraform) (DONE)
- **From:** NetBaseline (`sih26_ps26155/backend/app/parsers/rulepack.py`: block style as data), V.E.N.O.M. (reads
  Junos braces). Idea only.
- **Files:** `backend/app/structure/structured.py` (add next to `flatten_json`), `backend/app/structure/tokenizer.py`,
  the call site in `backend/app/api/routes/scan.py` (where `flatten_json` is used, line ~59 import),
  `backend/app/parsers/coverage.py` if coverage counts lines, tests in `backend/tests/` (new
  `test_structured_braces.py`), fixtures in `backend/tests/fixtures/seed_dialects/`, `docs/architecture.md`.
- **Prompt:**
  > Add `flatten_braces(text)` beside `flatten_json` in `backend/app/structure/structured.py`. Input is any
  > brace-block configuration (Junos `system { services { telnet; } }`, and later HCL). Output is one statement per
  > leaf, prefixed by its block path, in the same shape as Junos `set` lines: `system services telnet`,
  > `snmp community public authorization read-only`. Handle `;` terminators, quoted strings with spaces, `[ a b ]`
  > lists (one statement per item), `/* */` and `#` comments, `inactive:` prefixes (skip, and say so in coverage),
  > nesting of any depth. Keep a map from every flattened statement back to its original line number so evidence,
  > the Teach page and SARIF cite the real line in the uploaded file, not the flattened one. Decide whether to flatten
  > from structure (balanced braces, most lines ending in `{`, `}` or `;`), never from a vendor name. Then the
  > existing Junos `set`-style seeds in `backend/data/seed_recognizers.json` must read a braces file: write our own
  > braces fixture with the same settings as an existing set-style Junos fixture and assert both give the same
  > decided verdicts. Cisco IOS and FortiGate files must not be flattened (test). Real Junos braces files for
  > manual checking are in `datasets/batfish/juniper_junos/` (licence in `datasets/batfish/LICENSE`).
- **Checklist:**
  - [x] ~~`flatten_braces` + line map~~ set form at match time (see change below) + tests
  - [x] structural detection; IOS/FortiGate untouched (test)
  - [x] braces fixture = set fixture verdicts (test)
  - [x] citations point at original lines (test)
  - [x] benchmark not worse; docs
- **Change from the plan (2026-09-27):** the premise was wrong. `sample_juniper.conf` is **set-style**, not braces,
  and braces Junos was already read by 13 scoped seeds. The real gap: the 23 set-style and 13 brace-style Junos
  seeds each read only their own form (braces missed the SNMP community, retry limit, password length and
  `encrypted-password`). So there is no `flatten_braces` and no rewritten text. `set_form()` in
  `backend/app/facts/recognizers.py` lets unscoped recognizers also match a `;`-terminated brace leaf as
  `set <block path> <leaf>`. The statement keeps its own line, so no line map is needed. A leaf under a header
  that already answered the same setting is skipped (no double `user admin`). The tokenizer now blanks
  `/* */` comments (they were read as RouterOS `/section` headers) and drops `inactive:` lines and blocks
  (they were read as active: a false FAIL). `[ a b ]` lists stay one statement (the seeds already match the
  bracket form). 1.3 (Terraform) cannot reuse this: an HCL rule's verdict needs several lines of one block
  combined, so it needs its own design.

#### 1.2 MikroTik misses: default SNMP community and plaintext user password (DONE)
- **Files:** `backend/data/seed_recognizers.json` (MikroTik entries start around line 651),
  `backend/app/facts/recognizers.py` (`validate_recognizer`, the secret gate), `docs/seed-knowledge.md`,
  `benchmark/labels.json`, a fixture under `backend/tests/fixtures/seed_dialects/`.
- **Prompt:**
  > A RouterOS export with `/snmp community set [ find default=yes ] name=public` and
  > `/user set admin password=admin123 group=full` currently leaves MGMT-004 and MGMT-005 NOT_CONFIGURED. Add seed
  > recognizers for both, generalised with typed slots (the `[ find … ]` selector, any user name, `add` and `set`
  > forms). The password value is a secret: the recognizer must decide "plaintext password present" without the
  > template or any stored fact holding the value, and must pass the secret gate in `validate_recognizer`. If the
  > gate refuses it as designed, do not weaken the gate: add the narrowest documented exception and a test that the
  > value never appears in the stored recognizer, the scan response, the PDF or the ledger. Also check that
  > `name=public` on the default community fires MGMT-004 while a custom name does not. Add both settings to
  > `benchmark/labels.json` with a fixture we write ourselves.
- **Checklist:**
  - [x] SNMP default-community seed + test
  - [x] plaintext password seed + secret test (value never stored or shown)
  - [x] labels + benchmark
- **Change from the plan (2026-09-27):** MGMT-005 was not left NOT_CONFIGURED for a lack of any gate; it simply had
  no RouterOS seed. The password is read by an `{enum:storage}` slot on the word `password`, the value by `{any}`,
  so the secret gate passes unchanged. The SNMP seeds were refused by the gate for a false reason: the redactor
  read the slot `{community:RO}` as keyword `community:` + secret `RO}`. The one exception: slot arguments are
  hidden from the redactor (`_holds_secret`). Found on the way: a custom RouterOS community name leaked into the
  scan response (23 times on the sample, before this change too); redaction now scopes by `/section`
  (`redaction_paths`), and `_SET_NAME` also reads `name=`. Also seeded: `/ip service set telnet disabled=no port=23`
  (was only suspected). Not seeded: `add … write-access=yes` (RW), since the options come in any order.
  `test_resolution_queue.py` pinned the old Junos score: 1.1 made `juniper_edge.cfg` decide MGMT-005 PASS
  (`$6$` hashes), so (19, 24) → (38, 32); checked that this is the only changed verdict.

#### 1.3 Terraform (HCL) cloud security rules: AWS, Azure, GCP (DONE)
- **From:** V.E.N.O.M. (`engine/parsers/terraform_aws.py`, idea only).
- **Depends on:** 1.1.
- **Files:** `backend/app/structure/structured.py` (reuse `flatten_braces`), `backend/data/seed_recognizers.json`,
  `backend/data/platform_profiles.json` (N/A for device-management controls, as for AWS security groups),
  `backend/app/facts/lexicon.py` (cloud prefixes already listed near line 110), `backend/app/adaptive/vendor.py`,
  fixtures, `docs/seed-knowledge.md`, README vendor table.
- **Prompt:**
  > Make a Terraform file readable with no new dependency: HCL blocks are brace blocks, so reuse
  > `flatten_braces` and additionally handle `key = value` assignments, `resource "type" "name" {` headers (keep the
  > type in the statement path) and `[ "a", "b" ]` lists. Then add seed recognizers, one concept per dialect, for:
  > `aws_security_group` / `aws_security_group_rule` / `aws_vpc_security_group_ingress_rule` open to `0.0.0.0/0` or
  > `::/0` (all ports, and management ports 22/3389/23), `azurerm_network_security_rule` and inline `security_rule`
  > with `source_address_prefix = "*"` / `"Internet"` / `0.0.0.0/0`, and `google_compute_firewall` with
  > `source_ranges = ["0.0.0.0/0"]`. Map them to the same predicates the AWS JSON seeds use
  > (`boundary.policy.permit_any`, management exposure), so BOUNDARY-001, MGMT-003 and MGMT-010 decide. Extend
  > `platform_profiles.json` so device-only controls are N/A for these, decided from structure, not a vendor name.
  > Variables (`var.x`) and modules we cannot resolve stay UNKNOWN with the line cited, never PASS. Write our own
  > `main.tf` fixtures (insecure and secure) for each cloud; add them to `benchmark/labels.json`.
- **Checklist:**
  - [x] HCL flattening (assignments, headers, lists) + tests
  - [x] AWS, Azure, GCP seeds + tests
  - [x] platform N/A for Terraform + test
  - [x] unresolved variables stay UNKNOWN (test)
  - [x] fixtures + labels + benchmark; README vendor table
- **Change from the plan (2026-09-28):** `flatten_hcl` is its own function (1.1 has no `flatten_braces` to reuse).
  It keeps the file's line count: each block's header line becomes `<type> <labels> <own pairs, keys sorted> {`,
  assignment lines are blanked, braces kept. So evidence cites the rule block in the uploaded `.tf` (JSON still
  cites flattened lines), and a child block is read inside its parent: GCP puts `source_ranges` on the resource
  and the ports on `allow { }`, read with the resource header as the seed's scope. Unresolved references
  (`var.x`, `"${…}/32"`, function calls, heredocs) are written `${…}`, which no `{enum}` slot matches: they
  stay UNKNOWN, but with no line cited (no seed matched the line). 33 seeds (173 → 206). Azure and GCP seeds
  read open rules only (FAIL, never PASS): `*` cannot fill an `{enum}` slot because `*` is the table's
  wildcard. AWS reads restricted prefixes as PASS, like the JSON seeds. MGMT-010 stays NOT_CONFIGURED, as
  for AWS JSON: the JSON seeds never read it either, and MGMT-003 is the cloud form of that check. Other
  changes: `MAX_PATTERN_LENGTH` 256 → 320 (a standalone `azurerm_network_security_rule` template is 25 tokens,
  under the 32-token cap that actually bounds the regex); `platform_profile` looks at top-level lines only and
  a profile may list `roots`; lexicon knows `cidr_blocks`, `source_address_prefix`, `source_ranges`, … and
  `ingress` / `security_rule` as rule words; the upload box accepts `.tf`. A rule with extra attributes
  (`self`, `security_groups`, several CIDRs) matches no template: undecided, never wrong.

#### 1.4 Azure NSG and GCP firewall JSON exports (DONE)
- **Files:** `backend/data/seed_recognizers.json`, `backend/app/structure/structured.py` (flattening already
  works), `backend/data/platform_profiles.json`, fixtures, `docs/seed-knowledge.md`.
- **Prompt:**
  > `flatten_json` already turns cloud JSON into statements, but only 4 AWS seeds ship. Add seeds for
  > `az network nsg show` output (`securityRules[]` with `sourceAddressPrefix`, `destinationPortRange`, `access`,
  > `direction`) and `gcloud compute firewall-rules list --format=json` (`sourceRanges`, `allowed[]`, `direction`).
  > Only `access: Allow` + `direction: Inbound` / `INGRESS` from any source counts. Extend the platform profile so
  > device-only controls are N/A. Write our own fixtures from the public CLI output formats; labels + benchmark.
- **Checklist:**
  - [x] Azure NSG seeds + test
  - [x] GCP firewall seeds + test
  - [x] platform N/A + fixtures + labels
- **Change from the plan (2026-09-28):** "flattening already works" was not true for either format. GCP put a
  rule's ports (`allowed[{IPProtocol, ports[]}]`) on a separate line from its `sourceRanges`, and an inlined list
  of objects lost its key, so a `denied` rule would have read as a permit (false FAIL). `flatten_json` now:
  inlines an object of scalars / lists of scalars under its own key (AWS lines become `IpRanges CidrIp …`; the 4
  AWS JSON seeds and one test were updated); never inlines a named object (Azure rules got their own lines only
  because their empty `[]` arrays made them look non-flat); drops metadata (`etag`, `id`, `selfLink`,
  `creationTimestamp`, `kind`, `provisioningState`, `resourceGuid`) and `description`. 20 seeds (206 → 226):
  Azure for `nsg show` and `nsg rule list`, GCP with and without `logConfig` / one `targetTags`. Open rules only,
  as for Terraform Azure/GCP (`*` cannot fill an `{enum}` slot): a restricted rule stays undecided. Platform
  profiles for both, by top-level keys. ARM "export template" JSON (`properties` nesting) is not seeded.

#### 1.5 White-box: SONiC `config_db.json` and Cumulus (NVUE) (DONE)
- **From:** SurakshaSetu lists SONiC as "not implemented"; the problem statement names SONiC and Cumulus.
- **Files:** `backend/data/seed_recognizers.json`, `backend/app/adaptive/vendor.py` (`sonic` hint exists, line ~65),
  fixtures, `docs/seed-knowledge.md`, README vendor table.
- **Prompt:**
  > Add seed recognizers for SONiC `config_db.json` (flattened by `flatten_json`): `SNMP_COMMUNITY` entries with
  > `TYPE RO/RW` and default names, `SYSLOG_SERVER`, `NTP_SERVER`, `TACPLUS_SERVER` / `AAA`, `SSH_SERVER` /
  > telnet features where present. And for Cumulus NVUE (`nv set system …` lines and the `startup.yaml` form):
  > snmp-server, syslog, ntp, ssh. Only syntax we can cite from public vendor documentation: record the doc URL per
  > seed in `docs/seed-knowledge.md`, and leave out anything unsure. Fixtures written by us; labels + benchmark.
- **Checklist:**
  - [x] SONiC seeds + test
  - [x] Cumulus NVUE seeds + test
  - [x] sources recorded; README vendor table
- **Change from the plan (2026-09-28):** `flatten_json` did not read SONiC: all communities of `SNMP_COMMUNITY`
  merged into one line, and `SYSLOG_SERVER` / `NTP_SERVER` entries (`"10.0.0.5": {}`) vanished as empty values.
  An object whose values are all objects is now a table: one line per entry, an empty entry still states its
  key. Two leaks found and fixed: the SONiC community name (`SNMP_COMMUNITY` uses `_`, the redactor only knew
  `-community`) and the TACACS+ `passkey`. The keyword gate counts the words of an underscore identifier
  (`SYSLOG_SERVER` = 2), since SONiC table names are one token. 17 seeds (226 → 243), each with its
  documentation link in `docs/seed-knowledge.md`. Not seeded: SONiC `AAA authentication login "tacacs+,local"`
  (a comma cannot fill an `{enum}` slot), `SSH_SERVER POLICIES` (a dozen optional keys on one line),
  `NTP_SERVER … key …` (the gate reads `key` as a secret), Cumulus `startup.yaml` (no YAML reader ships; NVUE
  commands only), Telnet (Cumulus has no Telnet service). Known limit: the generic heuristic still *suspects*
  a disabled SONiC NTP server (`admin_state disabled … iburst on`: the last on/off word wins); it never decides.

### Phase 2: Proof, taken from V.E.N.O.M.

#### 2.1 Known vulnerabilities for the device's OS version (offline) (DONE)
- **From:** V.E.N.O.M. `engine/cve.py` + committed NVD cache (idea only).
- **Files:** new `backend/app/analysis/cve.py`, new `backend/data/cve_cache.json`, new
  `backend/scripts/build_cve_cache.py`, `backend/app/api/routes/scan.py` (device block, line ~774 builds
  `os_version`/`model`/`serial`), `backend/app/reporting/report.py` (device identification section),
  `frontend/src/app/Devices.jsx` and `frontend/src/app/Results.jsx`, `docs/api.md`, README.
- **Prompt:**
  > The problem statement asks for reports "customized based on the device's specific model and software version".
  > Add version-level CVE context. `backend/scripts/build_cve_cache.py` (run by hand, needs internet) queries the NVD
  > API 2.0 with `virtualMatchString` for Cisco IOS / IOS-XE, FortiOS and PAN-OS versions, keeps CVSS v3 critical and
  > high, top 5 by score per version, and writes `backend/data/cve_cache.json` with the generation date, source and
  > filter. `backend/app/analysis/cve.py` only reads that file: no network call in the scan path, a missing or broken
  > cache degrades to "no data" and never fails a scan. Match only when the file states the OS version (never
  > inferred); normalise to the vendor's train (IOS `15.2(4)M11` → `15.2`, FortiOS `7.0.12` → `7.0`). Show it on
  > Devices and in the PDF with the caveat "matched on version; a specific build may already carry the fix: context,
  > not an assessment", the cache date, and the NVD link per CVE. It must never change posture, coverage, risk,
  > findings or remediation (test that). Include it in the offline story: works air-gapped with the committed cache.
- **Checklist:**
  - [x] build script + committed cache (with date and filter)
  - [x] read-only matcher + tests (no version → nothing; broken cache → nothing)
  - [x] Devices page + PDF section with caveat
  - [x] test: scores and findings identical with and without the cache
- **Change from the plan (2026-09-28):** NVD's `virtualMatchString` does not prefix-match a train (Cisco lists
  exact builds such as `15.2(4)M11`), so the builder uses its version range (`versionStart` = the train,
  `versionEnd` = the next one). 45 trains: Cisco IOS 12.2-15.9, IOS-XE 16.3-17.15, FortiOS 5.6-7.6 (cache of
  2026-09-28, 106 KB). **PAN-OS is not covered:** its configurations rarely state a version and, without a parser,
  the platform is never confirmed, so a match could only be a guess. IOS vs IOS-XE is told apart by the release
  number (IOS-XE starts at 16).

#### 2.2 Prove each attack path and its "one fix" (DONE)
- **From:** V.E.N.O.M. (`samples/chain_*_pos.cfg` / `_neg.cfg`, `tests/test_attack_chains.py`,
  `engine/validation_summary.json`).
- **Files:** `backend/app/analysis/attack_paths.py`, `backend/tests/test_attack_paths.py`, new
  `backend/tests/fixtures/attack_paths/` (our own files), new `backend/scripts/build_path_validation.py`, new
  `backend/data/path_validation.json` (generated), `backend/app/reporting/report.py`,
  `frontend/src/app/AttackPaths.jsx`.
- **Prompt:**
  > For every chain in `backend/app/analysis/attack_paths.py`, write two minimal configurations ourselves: one where
  > the chain must appear, and a copy that applies only that chain's "fix here" step and changes nothing else. Write
  > the expected verdicts in the test before running the engine. Tests: the positive file shows exactly that chain
  > (and only the expected steps); the negative shows none of it; the diff between the two files is only the fix.
  > `build_path_validation.py` runs them and writes `path_validation.json` with the commit hash and date. The PDF and
  > the Attack paths page show one line: "Each path and its fix were checked against a positive and a negative
  > configuration (commit …)". A test fails if the JSON is older than the chain catalog (hash of the catalog stored in
  > it). Cover both Cisco and PAN-OS/seed-based chains.
- **Checklist:**
  - [x] positive/negative fixtures per chain
  - [x] tests with expectations written first
  - [x] generated validation JSON + staleness test
  - [x] line on the page and in the PDF
- **Done 2026-09-28:** 4 chains, 5 cases (the SNMP chain also on set-style Junos, read by seeds): each positive
  is a secure IOS base with only that chain's failures, so no other chain opens; each negative adds only the fix of
  the cheapest step (one line). Every expectation held on the first run. `catalog_hash()` fingerprints the
  catalog; the scan's `path_validation` (and so the page line and the PDF sentence) is `null` once it is stale.

#### 2.3 Held-out benchmark (labels before measuring) (DONE)
- **From:** V.E.N.O.M. (`tests/holdout/`, `tests/test_holdout_labels.py`: 27/31, labels committed first).
- **Files:** `benchmark/labels.json` (new `holdout` section), `backend/scripts/benchmark.py`,
  `benchmark/RESULTS.md` (generated), `backend/tests/test_benchmark.py`, README "Measured accuracy".
- **Prompt:**
  > Our current benchmark uses files we wrote seeds against. Add a held-out set: pick 6-10 real configurations never
  > used for seeds or tests, from `datasets/batfish/` (licence in `datasets/batfish/LICENSE`, source in
  > `SOURCE_COMMIT`), across at least 4 vendors. Label them by reading each file (setting, control, expected verdict,
  > line), commit the labels **in a separate commit before running the benchmark on them**, and never edit them
  > after (a test checks every label names an existing control and a line that exists in the file). Report the
  > held-out numbers as their own row: decided FAIL, suspected, undecided, missed, false alarms. Publish whatever
  > the result is; list every miss with its reason in RESULTS.md.
- **Checklist:**
  - [x] files chosen + labels committed first (own commit: `738ff1d`)
  - [x] label validity test (`backend/tests/test_heldout_labels.py`)
  - [x] held-out row in RESULTS.md and README, misses explained
- **Change from the plan (2026-09-28):** not Batfish. `datasets/batfish` had already been scanned (coverage run,
  2026-09-25) and mined for seed syntax, so it is not unseen; the user chose a new public source. Used
  pybatfish's example networks (Apache-2.0, commit `9f0f76f`, fetched to git-ignored `datasets/pybatfish/`):
  9 files, **3 vendor families** (Cisco IOS / IOS-XE incl. a zone firewall, Arista EOS, AWS security groups),
  not 4: the corpus has no Junos or PAN-OS. 34 labels, each citing its line. **First run: 20/21 detected,
  1 missed, 0 false alarms.** The miss was a real bug: the IOS parser ended an ACL at a `! text` comment line,
  so a later `permit ip any any` was never read and BOUNDARY-001 was a false PASS. Fixed (only a bare `!` ends a
  block) with a regression test; after the fix 21/21. Both numbers are published (RESULTS.md, README). Miss and
  undecided reasons live in `benchmark/heldout_reasons.json`, written after measuring (labels never edited).
  `test_benchmark.py` also requires 0 missed / 0 false alarms on the held-out set where it is fetched.

#### 2.4 Independent citation check (DONE)
- **From:** V.E.N.O.M. `verify.py` (checks every line number against the raw text).
- **Files:** new `backend/tests/test_citations.py`, reuse `isolated_engine()` from the CLI/benchmark
  (`backend/app/cli.py`, `backend/scripts/benchmark.py`).
- **Prompt:**
  > One test that runs every benchmark and demo file through the real pipeline and checks, independently of the
  > engine's own code: every cited line number exists in the uploaded text and the cited text is on that line
  > (after redaction); every attack-path step cites a decided FAIL of the same device; posture recomputed from the
  > returned results equals the returned posture. No new script: a test is enough.
- **Checklist:**
  - [x] citation test over all benchmark + demo files
- **Done 2026-09-28:** `backend/tests/test_citations.py`, 30 cases (29 files + the demo fleet scan). Nothing in
  the engine was wrong. The one real subtlety: a control can fail once per scope (per SNMP community, per
  interface), so an attack-path step is checked against all of that control's decided FAILs on the device. A
  JSON export is checked against its flattened lines (what the engine reads and cites by design); a Terraform
  citation must start with the uploaded block header. Checked that the test catches a line shifted by one, a
  path moved to another device and a posture off by one. `test_benchmark.py` floor raised 70 → 83.

### Phase 3: Submission deliverables

#### 3.1 Two-minute demo covers the new reach (DONE)
- **Files:** `docs/demo.md`, `demo-sih/` (add the Terraform and braces Junos files written in Phase 1),
  `frontend/e2e/demo.spec.js`.
- **Prompt:**
  > Update the 2-minute judge path in `docs/demo.md`: one bulk upload of a Cisco file, a PAN-OS file, a braces
  > Junos file and a Terraform file; show detection, the attack path and its proof line, the CVE context on the Cisco
  > device, teach one unknown line, rescan, ledger verify. Time each step; cut to 2 minutes. Extend the e2e test to
  > the same files so the demo cannot break silently.
- **Checklist:**
  - [x] demo script ≤ 2 minutes, timed
  - [x] demo files in `demo-sih/`
  - [x] e2e covers it
- **Change from the plan (2026-09-28):** "teach one unknown line, rescan" is not in the two minutes: it takes about
  40 s alone, so it stays step 7 of the full walkthrough. Everything else is in the path and in the e2e test, which
  times each step (30 s of machine time measured; 90 s of talk budgeted).

#### 3.2 Five-slide technical presentation (DONE)
- **Files:** `SIH2026-IDEA-Presentation-Format (1).pptx` (current deck), new `docs/presentation.pptx`.
- **Prompt:**
  > Five slides maximum: (1) problem and our answer in one line; (2) architecture (same diagram as the 2-page PDF);
  > (3) vendor-agnostic proof: vendors read, how (parser / seeds / structure flattening / teach), measured numbers
  > including the held-out row; (4) trust: AI proposes, human confirms, ledger, injection probe 0/6; (5) what the
  > judge saw in the demo and what is honestly not done. Every number from `benchmark/RESULTS.md` or a test.
- **Checklist:**
  - [x] 5-slide deck with sourced numbers
- **Done 2026-09-28:** `docs/presentation.pptx` (5 slides: problem and answer; architecture; vendor-agnostic proof
  with the planted / fixtures / held-out chart; trust; what the demo showed and what is not done). Every number is
  from `benchmark/RESULTS.md` or a test. The `.pptx` is git-ignored by the repo (`*.pptx`: submission artefacts
  go to the portal), so `docs/build_presentation.js` (pptxgenjs) is committed as its source. Checked with the
  OOXML validator and rendered through PowerPoint.

### Phase 4: Problem-statement gaps found against Crucible (`sih-samne/crucible-hamza`)

Added 2026-10-13. Crucible (Python, 6 parsers, YAML rules, signed ledger, Docker twin) was compared item by item
against the problem statement. It wins on four items the statement names word for word; this phase closes them.
Ground rule 1 holds: ideas only, no Crucible code or files. Branch `feat/ps-gaps` from `origin/main` (`f94e2f6`).

Not taken: the Docker twin sandbox (heavy; rescanning a copy already proves each fix on the file), the plain HTML
console (ours is ahead), YAML (the repo keeps knowledge as JSON and PyYAML is not a dependency), Merkle trees (the
ledger already hashes the whole redacted scan, so per-finding inclusion proofs add nothing a judge would use).

#### 4.1 Serial number and hardware from command output (DONE)
- **Files:** `backend/app/facts/identity.py` (new; `stated_identity` moved here from `heuristics.py`),
  `app/api/routes/scan.py`, `app/collect/collector.py`, `app/api/routes/collect.py`, `app/models/normalized.py`,
  `app/analysis/engine.py`, `app/api/schemas.py`, `app/reporting/report.py`, `frontend/src/app/Devices.jsx`,
  `frontend/src/app/Results.jsx`, `tests/test_identity.py`, `tests/test_live_collection.py`.
- **Checklist:**
  - [x] `show version` / `show inventory` / `show chassis hardware` / `get system status` / `show system info` /
        `display version` output recognised by lines only output prints (Cisco, Junos, FortiOS, PAN-OS, Arista, Huawei, MikroTik)
  - [x] paired by stated hostname, then file name, then "only one configuration"; a different hostname never pairs
  - [x] never scanned as a device, never decides a check (test: same verdicts and posture with and without it)
  - [x] unpaired outputs reported (`unpaired_outputs`), output alone refused with 400
  - [x] live collection runs the read-only identity commands in the same session (NAPALM: `get_facts`)
  - [x] PDF and Devices page name where the serial came from (`identity_source`)

#### 4.2 Step-by-step device commands, lockout-safe order (DONE)
- **Files:** `backend/app/remediation/cli.py` (new), `app/remediation/engine.py` (`FIX_ORDER`, `cli` on Outcome),
  `app/remediation/writeback.py` (phase order, reference commands), `app/api/routes/remediation.py`,
  `app/api/schemas.py`, `app/reporting/report.py` (naive `_diff_commands` removed), `frontend/src/app/Fix.jsx`,
  `frontend/src/index.css`, `tests/test_remediation_cli.py`, `frontend/src/app/Fix.test.jsx`.
- **Checklist:**
  - [x] verified fixes written as the dialect's own CLI: IOS-style blocks with `no`, FortiOS `config`/`edit` with
        `unset`, Junos/PAN-OS/VyOS `set`/`delete`, Junos braces as full-path `set`/`delete`, Huawei `undo`, RouterOS sections
  - [x] fixes applied and printed in phase order (0 safe path, 1 harden, 2 switch off, 3 restrict access)
  - [x] plan-level `cli` (whole sequence, entered and saved once) in the API, PDF and Fix page
  - [x] Junos, PAN-OS and Arista reference commands in `controls.json`; tried and verified like any write-back when
        complete and flat; otherwise shown as `reference_cli`, labelled NOT verified, with `<value>` placeholders
- **Change from the plan:** "verified recipes for PAN-OS, Junos and Arista" became reference commands in data plus
  verification where the engine can read them. Removals (`delete system services telnet`) cannot be verified on
  the generic path because absence is never a pass there; they stay labelled references. Measured on the sample
  and seed fixtures: Junos `juniper.cfg` 1 -> 3 verified fixes; PAN-OS and Arista unchanged in count, but every
  unverified control now shows the vendor command.

#### 4.3 Checks as data (DONE)
- **Files:** `backend/data/controls.json` (new, generated from the old Python catalog, content identical),
  `app/controls/catalog.py` (loader + validation), `app/controls/judges.py` (`BUILT_IN`, `rule_judge`, `judge_for`),
  `app/controls/evaluate.py`, `app/facts/recognizers.py` (declared booleans), `app/api/routes/scan.py` and
  `app/cli.py` (framework list from the data), `tests/test_controls_data.py`.
- **Checklist:**
  - [x] all 24 checks, mappings, phases and reference commands in one JSON file
  - [x] a new check needs no code: rule judges (`forbid` / `require` / `max` / `min`) and declared boolean predicates
        (test adds a PCI-mapped FTP check from data only)
  - [x] the file is validated at start: unknown predicate, judge, kind, severity, vendor or phase stops the load
  - [x] the framework list (API, CLI) comes from the mappings, so a new framework is data too
- **Change from the plan:** JSON, not YAML (see above). Built-in judges stay in Python for the 24 shipped checks:
  their vendor advice and edge cases (NTP, IPsec proposals, password storage) do not fit a one-line rule.

#### 4.4 Signed audit ledger (DONE)
- **Files:** `backend/app/ledger.py`, `app/db/database.py` (migration v8, SQLite and Postgres), `app/config.py`
  (`LEDGER_SIGNING_KEY`, `LEDGER_TRUSTED_KEYS`, `ledger_key_path`), `app/api/routes/ledger.py` (`/public-key`,
  `/export`), `app/cli.py` (`ledger-verify`), `app/reporting/report.py`, `requirements.txt` (`cryptography`),
  `.gitignore` (`*.pem`), `tests/conftest.py`, `tests/test_ledger_signing.py`.
- **Checklist:**
  - [x] every entry signed (Ed25519 over its hash); key generated owner-only on first use, or from the env
  - [x] a rewritten chain (entry edited, every later hash recomputed) is caught by the signature
  - [x] a signature by an untrusted key is refused; pre-signing entries still chain and are counted `unsigned`
  - [x] offline check of an export with only the public key, exit 0 / 1
  - [x] PDF names the signing key
- **Watch when merging:** `feat/generalize-recognizers` (`57018b1`) also adds a migration v8. Whichever branch
  merges second renumbers its migration to v9 (SQLite list and the Postgres list).

---

## Progress log

| Date | Item | Commit | Notes |
|---|---|---|---|
| 2026-09-27 | Comparison with V.E.N.O.M. and the problem statement; this plan | (not committed: `updates.md` is git-ignored since a8f3a05) | Their 147 tests pass. Cross-run results are in "Why this round". Old plan: `git show 0618e5e:updates.md`. |
| 2026-09-27 | 0.1 One set of numbers | `9603c9a` (final-updates) | Fresh run: backend 1509 passed / 2 skipped (5 min, `-n auto`), frontend 149, benchmark 18/20 + 70/87, 0 missed, 0 false alarms; catalog 23 checks / 78 requirements. Stale numbers fixed: README "Testing" 1227/119 → 1509/149; recognizers 161 → **165** (README, architecture, brief, seed-knowledge); predicates 16 → **23** (brief, architecture, data-model); brief "eight dialects" → eleven; testing.md seed test covers eleven dialects, not eight. |
| 2026-09-27 | 0.2 Architecture PDF | `9603c9a` (final-updates) | `backend/scripts/build_architecture_pdf.py` renders the brief's Markdown subset with ReportLab (no new dependency), exits 1 over 2 pages. `docs/architecture-brief.pdf`: 2 pages, page 2 about one-third full. README links the PDF. |
| 2026-09-27 | 1.1 Brace blocks read by set-style seeds | `9603c9a` (final-updates) | `set_form` in `recognizers.py`, `/* */` and `inactive:` in `tokenizer.py`; `tests/test_structured_braces.py` (10); fixture `junos_braces.conf` = `junos_set.conf` (extended with SNMP community, retry, password length). V.E.N.O.M. sample as braces: 5 → 7 problems (+MGMT-004, MGMT-011 at the real line 35). Benchmark unchanged: 18/20, 70/87, 0 missed, 0 false alarms. Docs: architecture.md §3, seed-knowledge.md. |
| 2026-09-27 | 1.2 MikroTik SNMP community + plaintext password | `9603c9a` (final-updates) | Full suite 1530 passed / 2 skipped; test counts and the architecture PDF refreshed. 8 seeds (165 → 173); `_holds_secret` slot-argument exception; `redaction_paths` + `name=` redaction; `tests/test_mikrotik_credentials.py` (9, incl. secrets absent from recognizers, scan, PDF text and ledger), 2 redaction leak cases; fixture `routeros_credentials.rsc` labelled. V.E.N.O.M. MikroTik sample: 3 → 7 problems (MGMT-001, -004, -005, -011 decided). Benchmark: planted 18/20, fixtures 70/87 → **73/91**, 0 missed, 0 false alarms. README, architecture, brief, demo, roadmap, seed-knowledge counts updated. |
| 2026-09-28 | 1.3 Terraform (AWS, Azure, GCP) | `9603c9a` (final-updates) | Backend 1547 passed / 2 skipped, frontend 149 (run alone: under load 6 frontend tests time out at 5 s). `flatten_hcl` + scan wiring; 33 seeds; Terraform platform profile (20 checks N/A); `tests/test_terraform.py` (17); fixtures `backend/tests/fixtures/terraform/` (insecure + secure per cloud, one with variables), 6 labelled. V.E.N.O.M. `main.tf`: nothing read → MGMT-003 FAIL (lines 55, 63), BOUNDARY-001 FAIL (line 71), 20 N/A. Benchmark: planted 18/20, fixtures 73/91 → **79/97**, 0 missed, 0 false alarms (74 secure: 62 confirmed, 12 undecided). Docs: README vendor table + counts, architecture §3, brief, seed-knowledge, demo, roadmap. |
| 2026-09-28 | 1.4 Azure NSG and GCP firewall JSON | `9603c9a` (final-updates) | Backend 1558 passed / 2 skipped (frontend untouched). `flatten_json` keeps inlined keys, lists of scalars, named objects apart, drops metadata; 20 seeds; 2 platform profiles; lexicon `allowed` / `denied`; `tests/test_cloud_json.py` (11); fixtures `backend/tests/fixtures/cloud_json/` (insecure + secure each), 4 labelled. Benchmark: planted 18/20, fixtures 79/97 → **83/101**, 0 missed, 0 false alarms (78 secure: 62 confirmed, 16 undecided). Docs: README vendor table + counts, architecture §3, brief, seed-knowledge (format links), demo, roadmap, testing. |
| 2026-09-28 | 2.4 Independent citation check | `8f6ce5f` (final-updates) | Backend 1588 passed / 2 skipped. `tests/test_citations.py` (30): every cited line and its text, attack-path steps against decided FAILs of the same device, posture/coverage recomputed from the results. All pass; the test catches a shifted line, a path on another device, a posture off by one. Benchmark test floor 70 → 83. |
| 2026-09-28 | 1.5 SONiC and Cumulus NVUE | `3beb003` (final-updates) | Backend 1604 passed / 2 skipped. `flatten_json` tables; 17 seeds with sources; redaction of `SNMP_COMMUNITY` names and `passkey`; keyword gate counts underscore words; `tests/test_sonic_cumulus.py` (9), 3 redaction leak cases; 4 fixtures labelled. Benchmark: planted 18/20, fixtures 83/101 → **89/112**, 0 missed, 0 false alarms; benchmark test floor 83 → 89. Docs: README (vendor table, counts), architecture §3, brief, seed-knowledge (sources), demo, roadmap, testing. |
| 2026-09-28 | 2.3 Held-out benchmark | `738ff1d` labels, `12f7e35` fix + results (final-updates) | pybatfish example networks, 9 files, 34 labels committed first. First run 20/21, 1 missed (IOS parser ended an ACL at a `! text` comment: false PASS on BOUNDARY-001), 0 false alarms, 11/13 secure confirmed. Parser fixed + regression test: 21/21. `benchmark.py` held-out group (skipped when not fetched), `heldout_reasons.json`, README row. |
| 2026-09-28 | 2.2 Attack-path proof | `5c4781a` (final-updates) | `tests/test_path_proof.py` (17), 10 fixtures in `tests/fixtures/attack_paths/`, `scripts/build_path_validation.py` → `data/path_validation.json` (5 cases, 4 chains, passed), `catalog_hash()` / `validation()` in `attack_paths.py`, `path_validation` in the scan response, PDF sentence, page line (+1 frontend test). Docs: api.md, testing.md. |
| 2026-09-28 | 2.1 CVE context by OS version | `6d77412` (final-updates) | `scripts/build_cve_cache.py` (NVD API 2.0, version ranges), `data/cve_cache.json` (45 trains), `app/analysis/cve.py`, `devices[].known_cves`, Devices page + PDF section with caveat, `tests/test_cve.py` (10) incl. identical scores with and without the cache, `Devices.test.jsx` (1). Docs: api.md, README, testing.md. |
| 2026-09-28 | 3.1 Two-minute demo | `0d7b488` (final-updates) | `demo-sih/juniper_edge_braces.conf`, `demo-sih/aws_edge.tf`; `docs/demo.md` two-minute path with measured machine seconds; `frontend/e2e/demo.spec.js` scans the four files, checks CVE context and the path proof, writes `demo-timings.json`: passed in 30.5 s. |
| 2026-09-28 | 3.2 Five-slide deck | `8918751` (final-updates) | `docs/presentation.pptx` built by `docs/build_presentation.js`; validator passed; rendered via PowerPoint and two layout defects fixed (arrow direction, list alignment). |
| 2026-09-28 | Full test run + website run | `ae9e56a` (final-updates) | Backend 1644 passed / 2 skipped, frontend 151, e2e 1 (30.5 s), benchmark 18/20 · 89/112 · held-out 21/21, 0 missed, 0 false alarms. Three files scanned through the website locally (Cisco IOS-XE, brace Junos, Terraform): results in `output.md`. The run found a 1.1 gap: a brace header (`community … {`) was read again by the heuristic, downgrading MGMT-004's confirmed PASS; fixed for per-object settings, regression test added. Two display issues recorded as open in `output.md` §3 (HTTP finding shows the SSH line first; "19 of 20" vs "19 of 23"). |
| 2026-09-28 | Demo video files (outside the plan) | `df2a0b3` (final-updates, pushed) | User request after the plan was done. `demo-sih/` now holds three fix-to-100 files (Cisco 41 → 100 by one-click fixes; PAN-OS 30 → 100 by seed write-back + 5 verified commands; unknown vendor taught 3 lines, then fixed to 100), pinned by `tests/test_demo_fix_to_100.py` (3). The four earlier demo files moved to `backend/tests/fixtures/demo/`; 17 tests, benchmark labels, e2e and docs repointed (356 affected tests + benchmark passed; full suite not rerun, at the user's request). Fix page offers *Ask AI for a command* after a rejection; the prompt carries the rejected command (redacted) and its reason (+1 backend, +1 frontend assertion). `docs/demo-video.md` rewritten as the video script. Change from plan: none of the plan items changed. Note: trial runs wrote 3 taught recognizers to the user's Postgres database (`DATABASE_URL` set); rows 254–256 were disabled again. |
| 2026-09-28 | Repo cleanup for judges (outside the plan) | `bf75c36` (main, not pushed) | `final-updates` merged into `main` (fast-forward) and pushed; local `phase-2` deleted (stale, superseded). Removed: `backend/full_test_output.txt`, `backend/test_api.py`, `backend/diagnose_remediation.py`, root `sample_cisco_insecure.cfg`, `docs/project-audit.md`. Untracked but kept on disk (git-ignored): `docs/study.md`, `docs/demo-video.md`, `output.md`. Links in README and `docs/demo.md` updated. |
| 2026-09-29 | Teach tabs, learned page, fleet demo (outside the plan) | `65e3e26` (main, not pushed) | Adaptive learning split into "Found in your file" / "Everything else"; Learned mappings moved to its own sidebar item; `_draft_template` reads a unit written as its own word (`0 minutes`), found while recording; `demo-sih/fortigate/` three-device fleet (80 → 100, remote-takeover path on HQ, NTP mismatch); Cisco demo at 16.9 for CVE context. Tests: frontend 152, demo tests 5, recognizer/teaching/benchmark 426 passed (full backend suite not rerun). License `LICENSE` added and pushed earlier (`624719f`, `5542306`). A rejected line (#2, `operator inactivity-lock 0 minutes`) removed from Supabase; the app has no undo for rejections yet. |
| 2026-10-03 | Optional accounts (outside the plan; changes ground rule 2) | `7a989ee` (feat/supabase-auth, merged into main and pushed with `f6fca47`, `71b280c` on 2026-10-03; production moved to a new Supabase project) | User request: a visitor could list everything anyone taught (`GET /api/adaptive/mappings` open). `SUPABASE_URL` on: Bearer token = account's own knowledge in the main store, `X-Guest-Id` = one browser's, kept only in the local SQLite file (wiped with Render's disk); seeds shared and read-only to accounts; pre-account runtime rows hidden until claimed by SQL (docs/deployment.md). Migration 7 (SQLite + Postgres): `owner_id`, rejections unique per owner. `app/auth.py` checks tokens with Supabase `/auth/v1/user` (cached 60 s, no new backend dependency); frontend `@supabase/supabase-js`, sign-in in the app bar, guest warning on Teach and Learned. Tests: `test_accounts.py` (10), `Account.test.jsx` (3); backend 1660 passed / 2 skipped, frontend 155 (2 load timeouts in the full run pass alone, as before). Docs: api.md, security-model.md, deployment.md (incl. checking production behaviour locally), .env.example. Not done: scans are still not tied to accounts. Follow-up `f6fca47`: Postgres migration enables row level security on every backend table (the anon key is public now; owner role bypasses it), untested against a live Postgres. Follow-up: Supabase egress 5.83 / 5 GB (grace until 30 Oct): drift read up to 200 archived responses (~116 KB each) per Overview view, history status read whole scans; now LIKE-filtered to 3 candidates per device and `SELECT 1` (tests in test_drift.py, 2). |
| 2026-10-03 | Production hang after the deploy (outside the plan) | `6995c47` (main, pushed) | Render logs: `password authentication failed for user "postgres"` on the new Supabase project, then `ECIRCUITBREAKER`. Cause: Render `DATABASE_URL` missing the `postgres.<ref>` user. Each database call waited 30 s (pool timeout) on the event loop, so even `/health` hung. Pool timeout now 5 s; the URL itself is fixed on Render by the user. |
| 2026-10-03 | Slow production scans (outside the plan) | `4eac558` (main, pushed) | Browser timing on production: scan 24-29 s, drift 5-9 s, plan 8.5 s; local 0.7 s. Profile: `compile_pattern` ran 26,487 times per scan (same templates per line). `lru_cache` on `compile_pattern` and `recognizer_slot`: local scan 0.3 s. Backend 1662 passed / 2 skipped. Found too: local `backend/.env` pointed at the production database. |
| 2026-10-03 | Prod timing after `4eac558` + store cache (outside the plan) | `77d0ecc` (main, pushed) | Prod after the template cache: plan 9 s → 1.4 s, teach queues 9 s → 1.4 s, but scan still 21-29 s and drift 6.5 s, which CPU alone does not explain (local scan 0.3 s). SQLite store reads now cached like Postgres (local scan 0.19 s, plan 0.14 s); `Server-Timing` header (pg / sqlite / total) on every response to find what the scan spends on Render. Backend 1662 passed before the header; 225 related tests after. |
| 2026-10-03 | Scan archive off the request path (outside the plan) | `bd43c15` (main, pushed) | Prod with Server-Timing: scan 20.8-21.4 s server time, drift 5 s, health 1 ms (requests sent one at a time). Prod replicated locally (guest scope + the real Supabase): steady scan 1.9 s of which Postgres 1.7 s (save_scan 1.0 s, ledger 0.7 s), drift 1.3 s all Postgres. Archive = 84% of scan CPU. Now on one background worker (order kept for the ledger chain; tests run it inline). Local scan response 0.21 s -> 0.14 s. Backend 1663 passed / 2 skipped. Server-Timing showed no pg time on Render though there is some: unpinned dependencies on Render may differ, not chased. |
| 2026-10-04 | Reverted all of the 2026-10-03 work on GitHub (user request) | `5cc0fd7` (main, pushed) | One revert commit undoing 7a989ee..bd43c15; tree identical to 65e3e26 (user's teach tabs commit kept). User is moving testing to a new repository. Ground rule 2 (no accounts) holds again. The new Supabase project still has migration 7/8 (owner_id, rejected_lines unique per owner, RLS): the old code's ON CONFLICT (line_key) for rejections will fail against it, so pair the old code with a fresh database. |
| 2026-10-04 | Production database login and egress fix on main (outside the plan) | `6854630` (main, pushed, live on Render) | Render could not log in to the new Supabase project with a password holding `@` and `$$`, though the identical URL worked locally over IPv4 and IPv6; the percent-encoded form (`%40`, `%24`) set on Render works. Yesterday's 21-29 s scans were these failing database calls (5 s timeouts), not CPU: with logins working a scan takes ~3 s. New project archive: 14 scans, avg 149 KB, so the reverted code downloaded ~2 MB per Overview view, ~30 MB at the 200 cap. Cherry-picked only 71b280c (drift: at most 3 candidates per device; history: SELECT 1). Drift 2.3 s -> 0.9 s. Remediation plan still ~17 s on Render (template cache 4eac558 not on main). Local work stays on branch feat/supabase-auth. |
| 2026-10-04 | Speed changes on main (outside the plan) | `52866c3`, `a648a4c`, `272c5ae` (main, pushed, live on Render) | Cherry-picked 4eac558, 77d0ecc, bd43c15 onto main without the accounts code (two conflicts resolved by dropping owner/args; conftest keeps only ARCHIVE_INLINE). Backend 1653 passed / 2 skipped. Local: scan 0.11 s, plan 0.14 s. Live (warm, unknown-vendor file): scan 0.5 s, plan 3.5 s (was 17 s), drift 0.6 s, teach/learned/history pages 0.1-0.4 s, results unchanged (HQ-EDGE-RTR02 41/100), no console errors. |
| 2026-10-04 | Phone layout fix (outside the plan) | `f122f9b` (branch fix/mobile-ui, pushed; main untouched) | At 390px every page sat in a narrow right column with sideways scroll: a later `--side: 248px !important` (chat rail rule, max-width 900px) overrode the 960px strip layout. Now `--side: 0px !important` at 960px and the 900px override removed; `.ov-actions` loses its 19rem basis when the overview header stacks. Checked 13 pages at 390px against the live backend: page width = screen width on all. Frontend 152 passed (one load timeout in the first run, passes on rerun). |
| 2026-10-04 | Phone layout fix merged (outside the plan) | `f122f9b` (main, pushed) | fix/mobile-ui fast-forwarded into main; Vercel rebuilds the live frontend. |
| 2026-10-04 | Arista live test: false Telnet pass and AI answers (outside the plan) | `2db2907` (branch fix/heuristic-truth, not pushed) | Live scan of an Arista EOS file: engine passed MGMT-001 from `no shutdown` under `management telnet` (read as off), missed HTTP (`management api http-commands`); Ask-AI on 12 undecided checks gave 0 answers (3 real calls rejected by the citation check, 9 in 0.2 s); chat answered a bare "No." to Telnet and HTTP. Agreed with the user: a guess never passes any check; LLDP gets a clearer question. Fixes: `shutdown` is an off state (no shutdown = on) and a block state word; heuristic PASS -> UNKNOWN still marked heuristic, AI judge skips those; LLDP global message asks which interface faces the internet, top-level seed match scoped global; chat never answers bare yes/no from provisional/unknown/not configured. Tests: test_arista_management_blocks.py (4), test_phase5_heuristics.py expectations updated. Backend 1657 passed / 2 skipped; benchmark unchanged 18/20, 89/112, 21/21, 0 missed, 0 false alarms. Not done: why Ask-AI citations fail (needs a Groq key locally). |
| 2026-10-04 | Cisco-family and Arista seeds (outside the plan) | branch knowledge/seed-expansion | 11 seeds: NX-OS read-write `snmp-server community … group network-admin`, `banner motd`; ASA `ssh version`, `ssh timeout`, `password-policy minimum-length`, `aaa local authentication attempts max-fail`; `banner login` (ASA and IOS-XR); IOS-XR `exec-timeout` under `line`, `authenticate` under `ntp`; Arista `management telnet` block with `shutdown` / `no shutdown`. A login banner may end in `{rest}`. `exec-timeout 5 0` now reads 5 minutes; `0 30` (seconds) is never read as a disabled timeout. Left out with reasons in `docs/seed-knowledge.md` Limitations (ASA `telnet`, XR `ssh server v2`, NX-OS `cdp enable`, ASA `http server enable`). Tests: `test_seed_cisco_family.py`, `test_seed_knowledge.py`. `demo-sih/arista.cfg` added; `demo-sih/README.md` removed. Not committed yet: paused by the user before commit; not merged with origin/main. |
| 2026-10-09 | Fresh clone passes (outside the plan) | `a1c31ad`, `ba3b115` (branch fix/fresh-clone from origin/main, worktree `../sih-26155-fresh-clone-fix`, not pushed) | Reviewer's clean clone: 1848 passed, 24 failed, 8 errors. Backup first: `../sih-26155-backup-2026-10-09`. `.gitignore`: `teach/` -> `teach/*` + `!teach/*_5_configs/` (40 files, secret scan clean: only TEST-REDACTED, generic communities, private IPs). 4 `test_config_loading` cases skip without `backend/.env` + key. Two stale tests found once the files were present, both from 45c2a04/94f1fc1 behaviour that is intended: `no ip redirects` on one interface is UNKNOWN (test_checks_pack_d), Junos NTP auth is taught so LOG-002 fails on juniper_01 as labels.json says (test_learned_absence). No app logic changed. Benchmark regenerated (datasets copied into the worktree, still ignored): planted 19/20, fixtures 92/112 (README said 89), held-out 21/21. README marks held-out as needing the fetch; testing.md clean-clone section rewritten. Clean clone after `a1c31ad`: 1870 passed, 15 skipped (4 GROQ, 9 held-out, 2 live AI), 1 failed (fixed in `ba3b115`). Clean clone after `ba3b115`: 1871 passed, 15 skipped, 0 failed; benchmark planted 19/20, fixtures 92/112, 0 missed, 0 false alarms. |
| 2026-10-09 | fix/fresh-clone on main; main merged into seed work (outside the plan) | `ba3b115` (main, pushed by the user), `cca4740` WIP + `6cb45b3` merge (knowledge/seed-expansion, not pushed) | main already had 8 of the branch's 11 Cisco-family seeds (identical or label-only differences); kept main's, added the 3 new ones (NX-OS RW community, Arista `management telnet` shutdown / no shutdown): 383 seeds. recognizers.py: main's interface-local LLDP and redirect rules ahead of the branch's top-level LLDP = global. seed-knowledge.md: rows merged; "left out" list kept minus IOS-XR `max-servers`, which main now reads. Tests NOT run on the merge (stopped at the user's request). Docs still say 380 recognizers. Worktree removed, scratch clones deleted; backup `../sih-26155-backup-2026-10-09` kept. |
| 2026-10-09 | Docs: live link, run time, test counts (outside the plan) | `3beac55` (branch docs/live-link, pushed; fast-forward onto main left to the user) | README links https://netaudit-three.vercel.app/ (HTTP 200; Render backend /health 200 after a 33 s cold start; /api/assistant/status ai_available true, groq) with a ~30 s wake-up note. Serial pytest ~1 h noted next to `-n auto`; benchmark 14 s. testing.md and architecture-brief: 70 files, 753 functions, 1,886 cases (collected); brief PDF rebuilt. Checked on main and left as is: 0 broken links in 27 docs, 23 / 78 / 380 / 41 match the code, demo first scans 41/15, 30/10, none/3, 80/13 match a real CLI scan. |
| 2026-10-09 | Removed "Fix it for me" (user request, outside the plan) | `5b892ff` (branch fix/remove-fix-it-for-me, pushed; not on main) | It only removed cited lines (never adds a setting), so fixes were rarely good enough. Fix page for unconfirmed vendors: Ask AI (primary) + enter manually. Backend `POST /remediation/candidate/derive` kept (test_final_review uses it); ai-design.md says API only. demo.md step 10 removed, 11-14 renumbered, button name corrected to "Ask AI for a command". Frontend: Fix.test.jsx 18 + lib tests, 41 passed. |
| 2026-10-09 | Detection gaps from an independent benchmark (outside the plan) | `2ddaa50`, `f94e2f6` (branch feat/defaults-and-gaps, worktree `../sih-26155-gaps`, NOT pushed, awaiting approval) | Backup `../sih-26155-backup-2026-10-09-b`. Test first: 14 fixtures in `tests/fixtures/gaps/` (insecure + hardened per Junos hier, Junos set, PAN-OS, Arista, Huawei, MikroTik, FortiOS), `test_gaps.py` 24 failed before. Done: documented defaults with sources (Junos idle-timeout via learned absence; PAN-OS / Huawei VTY / RouterOS source restriction as value defaults), FAILs from a default now name it; mentions narrowed (management sources need a management word, a remote log needs a place off the device or an address); Arista `no shutdown` = on (tokenizer OFF_STATES from 2db2907 + the two management-telnet seeds), `protocol http`, `nopassword`; Huawei NTP `{rest}`, `rule N permit ip`, VTY `authentication-mode none`; RouterOS export-order seeds; `empty` storage, per-account password facts; FortiGate HTTP on any interface, per-ntpserver auth (all servers); new AUTH-004 root SSH login (N/A on IOS/FortiOS). Not done: Junos AUTH-001 default (Junos has retry-options defaults, silence is not "no limit"); RouterOS `/ip service set … address=` not read as restricted (one service of six; it only withholds the default); the "guess never passes" part of 2db2907 not brought over. Test changes explained in place: test_resolution_queue (Junos file now 27/43, three correct new FAILs), test_mikrotik_credentials (two password FAILs instead of one), test_phase2_controls (AUTH-004 + two NIST titles in the reference lists). Benchmark unchanged 19/20, 92/112, 21/21, 0 missed, 0 false alarms. 24 checks, 80 requirements, 396 seeds. f94e2f6: seed count 380 -> 396; seed_coverage/arista.conf said Telnet on and off (looked decided only through the 'no shutdown' misread), now both off; VyOS 'syslog global' is local, LOG-001 FAIL. Full backend (worktree, datasets present): 1918 passed / 3 failed (those three, fixed in f94e2f6, 150 rerun passed) / 6 skipped; frontend 152 passed (one Upload load timeout when run beside the backend, passes alone). Fresh clone of f94e2f6: 1912 passed, 15 skipped (4 Groq, 9 held-out, 2 live AI), 0 failed; benchmark 19/20, 92/112. |
| 2026-10-10 | RouterOS all-services-off follow-up (outside the plan) | `a75c48a` (feat/defaults-and-gaps, local only, not pushed) | feat/defaults-and-gaps was pushed at `f94e2f6` and fast-forwarded onto main at the user's request. Follow-up asked before that push: when all eight `/ip service` entries are `disabled=yes`, MGMT-003 no longer FAILs from the any-address default (`unless_all_off` in factory_defaults.json). 4 tests in test_gaps.py; backend 1924 passed / 6 skipped; vitest run was stopped by the user, so it is unverified there. Not pushed: waiting for the user. |
| 2026-10-10 | Recognizers generalize to realistic variants (outside the plan) | `57018b1` (branch feat/generalize-recognizers from main `f94e2f6`, worktree `../sih-26155-generalize`, NOT pushed, awaiting approval) | Backup `../sih-26155-backup-2026-10-10`. Test first: test_generalization_variants.py, 174 tests (97 failed before). A trailing options on toggles (no switch word, no leading negator); B options after values (off words, numbers, list words, RW words refused); C unit words; D key=value in any order + `set [ find ]` as `add`, k=v drafts; E dialect counts lines in its syntax read or not (cascade cause: `_dialect` counted only settings READ, MIN_UNDERSTOOD=3); F ASA `http server enable` = HTTPS, `encrypted` = legacy_md5 FAIL, migration v8. Change from the task: destination drafts do NOT end in `{rest}` (it forbids bare hostnames, which test_recognizer_generalization pins); options are read past anyway. Variant table 86/167 -> 167/167, no wrong readings before or after. Benchmark main 19/20, 92/112, 21/21, 0 FA -> branch 19/20, 93/112, 21/21, 0 FA. Changed expectations (reason in place): line_cases.json x2, seed count 399, migration v8. |
| 2026-10-13 | Phase 4 (4.1-4.4): serial from command output, device CLI in lockout-safe order, checks as data, signed ledger | `f80c149` (branch feat/ps-gaps from origin/main `f94e2f6`, NOT pushed) | Compared against sih-samne/crucible-hamza; ideas only. Numbers: Junos juniper.cfg verified fixes 1 -> 3, every unverified Junos / PAN-OS / Arista control now shows labelled reference commands. A security review flagged the first ledger verify as fail-open (stripped signatures passed as legacy); fixed before commit: an unsigned entry after a signed one is tampering, `fully_signed` reported, CLI exits 1 on unsigned entries unless --allow-unsigned. Stray key found: test_phase9 started a backend subprocess with the default key path; it now gets its own. Tests changed for intended behaviour: test_phase2_controls (remediation_keys field removed, same intent checked by id), test_pdf_report (new device-command and reference wording), test_seed_expansion (rebuilds the v6 ledger table before re-running migrations; expects the latest version). Backend 1970 passed / 2 skipped; frontend 153 passed; benchmark unchanged 19/20, 92/112, 21/21, 0 missed, 0 false alarms. Merge note: feat/generalize-recognizers also adds migration v8; whichever merges second renumbers to v9. Known limit: on Windows the key file's 0600 mode is not enforced (it inherits the folder's ACL). |
| 2026-10-13 | 4.1 follow-up: ReDoS in identity patterns | `5c9df83` (feat/ps-gaps, NOT pushed) | Commit review flagged ReDoS in app/facts/identity.py; confirmed (200 KB of blank lines > 5 min). Cause: multiline `^\s*` crossing newlines, a whole-file lookahead in the Junos signature, two unbounded runs in the Cisco version pattern. Fixed: spaces/tabs only in whole-text patterns, `^Junos: <digit>`, comma-bounded Cisco pattern, lines read to 300 chars, one search per pattern, blank lines skipped. 2 MB hostile input now 1-3 s; regression test with four hostile 2 MB inputs. test_identity + test_live_collection 55 passed; pdf/ui/cli/remediation_cli 52 passed; benchmark unchanged 19/20, 92/112, 21/21. |
| 2026-10-13 | Phase 4 merged and pushed | `f80c149`, `5c9df83` (main, pushed at the user's request) | Fast-forward of main to feat/ps-gaps (origin/main had not moved from `f94e2f6`). The live Render backend wipes its disk on restart: it needs LEDGER_SIGNING_KEY set, or each restart signs with a new key and older entries verify as 'not a trusted key'. |
| 2026-10-13 | Unseen-vendor fixes from the Nokia SR OS test (outside the plan) | COMMIT (branch fix/nokia-findings from main `5c9df83`) | Head-to-head with Crucible on an unseen Nokia SR OS config (datasets/batfish/nokia_sros) exposed three gaps. (1) A weak-crypto FAIL cited the strong algorithms too (lines 220/243 aes256-ctr): `combine` now cites only the lines whose reading made an any-predicate true. (2) Hostname `system { name "r1" }` was never read: `generic_hostname` now takes a bare `name X` directly in a `system` block (never a cipher, user or policy name). (3) VPN / firewall-policy checks could only be N/A through a dedicated parser: `feature_words` in data/controls.json (CRYPTO-001, LOG-003); on a configuration no parser reads, an undecided check is N/A when the dialect is understood and no line (comments included) uses any of the words; the reason lists them. Nokia result: original FAIL now cites 232, 255, 278, 298 only; hostname r1; hardened file CRYPTO-001 N/A, LOG-003 rightly undecided (it has ip-filter rules), coverage 43% -> 45%. Tests: test_unseen_vendor_fixes.py (11). Benchmark unchanged 19/20, 92/112, 21/21. |
| 2026-10-26 | Add Vercel Analytics to the React frontend (outside the plan) | Not committed; awaiting user approval | Installed `@vercel/analytics` and mounted its React `<Analytics />` component in `frontend/src/main.jsx`. No push or commit performed. |
