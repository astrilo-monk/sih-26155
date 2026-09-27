# NetAuditAI

Configuration security auditor for network devices, built for Smart India Hackathon 2026
(SIH26155 -AI-Driven Multi-Vendor Network Security Compliance Auditor, NTRO, Cybersecurity).

NetAuditAI answers 23 security questions (**controls**) about every uploaded configuration, cites the
configuration lines behind every answer, keeps what it could decide separate from what it could not, and
fixes confirmed Cisco / FortiGate findings with deterministic changes that are verified by a rescan.
Where the vendor cannot be confirmed it does not invent commands: an administrator (or, on request, the
AI) proposes one, NetAuditAI checks it against the uploaded configuration, and a person confirms it.
AI is optional: it only proposes answers for controls the deterministic engine left undecided, and a
human confirms them before they count. Configurations can be uploaded or pulled from a device over SSH;
NetAuditAI only ever **reads** a device, and never executes a change on one.

## Highlights

* **Measured, not claimed.** 18/20 planted vulnerabilities detected as decided FAILs, 83/101 on labelled fixtures from
  8 vendors with no dedicated parser, Terraform for AWS, Azure and GCP, and Azure / GCP firewall exports, **0 missed and 0 false alarms**; a test fails the build if that gets worse.
* **Potential attack paths.** Findings chained into how an attacker gets in (reach the login → capture the password
  → log in as admin), each step a decided FAIL with its line, plus the one fix that breaks the path.
* **Every verdict traceable.** Framework requirement → check → vendor-neutral field and value → the configuration
  line → verdict, in the finding drawer; the whole model can be compared across vendors side by side or exported.
* **Fixes that are proven.** Every automatic fix is applied to a copy and rescanned before it counts; a missing
  syslog server or banner is added in the device's own syntax from a validated value.
* **Tamper-evident audit ledger.** Scans, taught recognizers, fix decisions and reports are hash-chained; editing
  any entry is caught, and a report PDF can be checked byte for byte.
* **AI that cannot change a verdict.** Configuration text is fenced as data in every prompt; a live probe of 6
  prompt-injection attacks succeeded 0 times, and a fully hijacked model is tested to change nothing.
* **Contextual risk.** Worst problem, internet exposure, attack paths and asset importance, by a formula shown on
  screen and in the report.
* **Changes since the last audit.** Rescan a device and see what got fixed, what newly broke and which attack paths
  closed, from the redacted scan archive only; losing evidence is never counted as a fix.
* **Problems only visible across devices.** The same SNMP community on several devices (matched by hash, never
  shown) and devices using different NTP or syslog servers.
* **Your own baseline.** An organisation policy file tightens the limits (idle timeout, login attempts, password
  length) and names approved NTP / syslog servers; it can only tighten, never loosen ([docs/policy.md](docs/policy.md)).
* **Runs offline and in CI.** `LOCAL_AI_URL` sends every AI call to a local model (Ollama, llama.cpp) so nothing
  leaves the network; `python -m app.cli scan` fails a pipeline on a decided problem and writes SARIF
  ([docs/cli.md](docs/cli.md)).

## Status

Working hackathon prototype. Backend: 1588 tests passed, 2 live-AI tests skipped (`pytest -n auto` runs them in
parallel). Frontend: 149 tests passed, production build OK. One end-to-end browser test walks the demo path
(`cd frontend && npm run e2e`).

## Measured accuracy

Every labelled configuration through the real pipeline, shipped knowledge only, **no AI**
(`python backend/scripts/benchmark.py`, full table in [benchmark/RESULTS.md](benchmark/RESULTS.md), labels in
[benchmark/labels.json](benchmark/labels.json)):

| Set | Insecure settings detected (decided FAIL) | Missed | False alarms on secure settings |
|---|---|---|---|
| 20 vulnerabilities planted in the demo files (Cisco IOS, PAN-OS) | **18/20** (+2 suspected) | **0** | **0** of 4 |
| 27 labelled fixtures: 8 vendors with no dedicated parser, Terraform (AWS, Azure, GCP), Azure NSG and GCP firewall exports | **83/101** (18 undecided) | **0** | **0** of 78 |

"Undecided" is an answer, not a miss: the engine shows the line and says what it would need, and never calls an
insecure setting secure. A test fails the build if any of these numbers gets worse.

## Pipeline

```text
Raw configuration: uploaded, or collected over SSH (Netmiko/NAPALM) .. app/collect/
  (read into memory, never written to disk)
  ↓
Vendor detection + parse coverage ..................... app/parsers/detector.py, coverage.py
  ↓ confirmed Cisco IOS / FortiGate            ↓ unknown or unverified vendor
Dedicated parser → PARSER facts               Generic tokenizer ......... app/structure/tokenizer.py
+ documented vendor defaults → DEFAULT          → confirmed recognizers → CONFIRMED facts
                                                → lexicon heuristics  → HEURISTIC facts (provisional)
  ↓
SecurityFacts: predicate, value, scope, cited lines, assurance ...... app/facts/
  (the vendor-neutral Security Baseline Model: GET /api/scan/{id}/baseline, "Download baseline (JSON)")
  ↓
Control evaluation: every control on every configuration ............ app/controls/
  ↓
Posture + coverage .................................................. app/analysis/scoring.py
  ↓ UNKNOWN / NOT_CONFIGURED controls (unknown vendors only)
AI judge: budgeted, redacted, cached (optional) ..................... app/ai/judge.py
  ↓
Deterministic citation verification → AI_VERIFIED proposal (never scored)
  ↓
Human confirmation (Adaptive learning) → recognizer saved (SQLite, or Postgres via DATABASE_URL)
  ↓
Future scans: the recognizer answers decisively, with no AI call
  ↓ decisive FAIL on a confirmed vendor        ↓ decisive FAIL on an unconfirmed vendor
Deterministic remediation ................    Candidate command (typed, or AI-proposed on request)
  → re-parse → re-verify .. app/remediation/     → validated → simulated on a copy of the file
                                                 → every control re-evaluated .. app/remediation/candidates.py
                                                 → administrator confirms (never executed anywhere)
```

Details: [docs/architecture.md](docs/architecture.md).

## Vendor support

| Configuration | How it is analyzed | Assurance | Remediation |
|---|---|---|---|
| Cisco IOS / IOS-XE (common patterns) | Dedicated parser, confirmed by grammar coverage | Decisive (parser facts; no Cisco defaults are assumed) | Deterministic, verified |
| Fortinet FortiGate (FortiOS with a `config firewall` / `config vpn` section) | Dedicated parser, confirmed by grammar coverage | Decisive; password storage and AAA are not read by the parser (UNKNOWN) | Deterministic, verified |
| Look-alikes (Arista EOS, NX-OS, IOS-XR, ASA, Dell OS10, Brocade, FortiSwitch) and mixed configs | Reported **unverified**, then the generic path | Provisional unless a recognizer is confirmed | No generated commands; candidate remediation once a finding is decisive |
| Terraform (`.tf`: AWS security groups and rules, Azure NSG rules, GCP firewalls) | Blocks flattened in place (one statement per block, on its own line), read by shipped seeds; device-only checks are N/A | Decisive for an open rule; a variable the file does not resolve stays undecided | No generated commands |
| Cloud exports (JSON: AWS security groups, `az network nsg show` / `nsg rule list`, `gcloud compute firewall-rules list --format=json`) | Flattened to one statement per rule, read by shipped seeds; device-only checks are N/A | Decisive for an open Allow / Inbound rule | No generated commands |
| Palo Alto, Juniper and every other vendor | **No dedicated parser.** Generic tokenizer, lexicon heuristics, confirmed recognizers, optional AI judge | Provisional; decisive only through confirmed recognizers | No generated commands; candidate remediation once a finding is decisive |

The vendor is decided deterministically. An AI vendor guess is reported as evidence only and never selects a parser, defaults or remediation.

**Shipped knowledge.** 226 reviewed recognizers for eleven unparsed dialects (Juniper Junos, Palo Alto PAN-OS,
Arista EOS, Huawei VRP, HPE Aruba AOS-CX, Check Point Gaia, Extreme EXOS, MikroTik RouterOS, Cisco NX-OS, ASA, IOS-XR), AWS security
groups, Azure NSG and GCP firewall exports and Terraform (AWS, Azure, GCP) ship in `backend/data/seed_recognizers.json` and load into an empty database on first start, so those dialects
answer several controls before anyone teaches anything. Each entry is one concept per dialect, generalized over
addresses, names, numbers and indentation through typed slots. They are ordinary recognizers -same templates,
same validation, same decisive CONFIRMED facts -and are marked `source=seed` so shipped knowledge can be audited
separately from what a deployment was taught. This is not a parser and not training: see
[docs/seed-knowledge.md](docs/seed-knowledge.md).

**Device identification** (API `devices[]` and the PDF report) states only what the file states: hostname, the
Cisco `version` line, and for FortiGate the model and firmware from the `#config-version=` export header when
present. Serial numbers and chassis details are never invented.

**Seed write-back** (unconfirmed vendors) fixes what a reviewed recognizer read: the recognizer that read
`disable-telnet no` writes `disable-telnet yes` in the same syntax, and the rescanned copy must show a decisive
PASS. Those fixes behave like a confirmed vendor's, including one corrected download. See
[docs/architecture.md](docs/architecture.md) §10.

**Candidate remediation** (unconfirmed vendors, once a finding is decisive) is a proposal, not a fix. The
administrator types the command, or asks the AI for one; NetAuditAI validates it, removes the cited
statements from an **in-memory copy** of the configuration, re-reads that copy with the generic engine and
re-evaluates every control. A verified candidate means *the finding is gone from this configuration file*
(typically `FAIL → NOT_CONFIGURED` -absence is never a PASS). It does not mean the command is safe to run
on the device, and it changes no posture, coverage, finding or download until the device itself is changed
and scanned again. NetAuditAI performs detection, candidate remediation, verification and human
confirmation; it does **not** execute commands on physical devices.

## Reading the results

- **Status** per control: `PASS`, `FAIL`, `UNKNOWN` (something relevant exists but could not be decided), `NOT_CONFIGURED` (nothing relevant found -never counted as PASS), `N_A`.
- **Assurance**: `parser`, `confirmed` (recognizer or administrator mapping) and `default` (documented vendor default) are **decisive**; `heuristic` and `ai_verified` are **provisional** ("Suspected FAIL", "Probable PASS", "AI proposes …").
- **Posture** = weighted PASS ÷ (PASS + FAIL) over decisive results; "-" when nothing was decided.
- **Coverage** = weighted share of applicable controls decided decisively. Posture and coverage are shown side by side, with the posture range if every undecided control failed or passed.
- **Critical not assessed** lists critical controls that were not decided.
- Provisional verdicts are shown with their evidence but never change posture, coverage, findings counts or remediation.
- **Framework views** regroup the same results under NIST SP 800-53 Rev. 5, the DISA Network Device Management SRG, ISO/IEC 27001:2022 Annex A and, for confirmed vendors, CIS Benchmarks. They are not a compliance certification.

The scan response still carries `score`, the deprecated penalty score (kept for existing scripts). The UI does not use it.

### The interface

A fixed left sidebar. **New scan · Overview · Devices · Findings · Remediation**, then under *Intelligence*
**Adaptive learning · Frameworks · History · Rules catalog · Audit ledger**. The scan pages are disabled until a scan
is open.

| Sidebar | Page | Route |
|---|---|---|
| New scan | Upload one or more configurations, or collect them from live devices over SSH; optionally say how important the device is and whether it faces the internet (risk only) | `#/app` |
| Overview | Risk (with its reasons), posture, coverage, **changes since the last audit** of the same device, a fleet view for several devices (with problems only visible across them), a link to the attack paths, the **vendor-neutral model** side by side per device, what to do now, PDF report, one-page executive summary, baseline JSON | `#/app/scan/{id}` |
| Devices | How each configuration was read (vendor, parser or generic path, coverage) | `…/devices` |
| Findings | Every control on every device, with evidence | `…/checks` |
| Attack paths | How the confirmed problems chain into an attack, per path: the steps with their lines, the outcome, and the one fix that breaks it; a summary of the fixes that close them all | `…/paths` |
| Remediation | **Fix in this order** (most risk removed per effort, with reasons), then fix automatically, needs your input, manual action, cannot safely fix; verified download; candidate fixes; **Next** rescores a copy with the commands you confirmed (shown as soon as one is) | `…/fix` |
| Adaptive learning | With a scan open: this scan's unknown syntax to teach. Otherwise: learned mappings (shipped and taught, each can be stopped) | `…/teach`, `#/app/learned` |
| Frameworks | The same results by framework requirement | `…/frameworks` |
| History | Scan summaries kept in this browser | `#/app/history` |
| Rules catalog | Every check, what it reads, and the 78 framework requirements the 23 checks answer | `#/app/rules` |
| Audit ledger | Hash-chained record of every scan, taught recognizer, fix decision and report; verify the chain, or check a report PDF (or the .zip of a multi-device scan) byte for byte | `#/app/ledger` |

Clicking a finding opens a drawer with its cited lines, assurance and framework mappings, and **how it was
decided**: framework requirement → check → normalized field and value → configuration line → verdict. When AI is configured,
**Explain this** asks for a plain-language explanation, labelled *AI-written, commentary, not evidence*; it never
changes a status, severity or count.

The left rail also holds an **assistant**: ask about the open scan and it answers from that scan's own redacted
results. It is told the verdicts as facts, and that an undecided check is not a failure, so it explains coverage
rather than inventing a pass. The panel can be resized, popped out and dragged anywhere; the rail keeps its width
whether the panel is open or shut, so opening it never reflows the page. Answers are rendered from Markdown into
React elements, never HTML, so nothing a model writes can inject markup.

Severity is a four-square meter plus the severity word, and status is a label with a square marker, so no result
is conveyed by colour alone. The palette is near-black, greys and one orange accent. Text is Inter; JetBrains Mono
is used only where characters must line up (configuration lines, evidence, diffs, commands, recognizer patterns).

## Setup

Prerequisites: Python 3.10+, Node.js 18+. A Groq API key is optional.

```bash
# backend
cd backend
python -m venv venv
venv\Scripts\activate          # Windows; macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# frontend (second terminal)
cd frontend
npm install
npm run dev                    # http://localhost:5173
```

Copy `backend/.env.example` to `backend/.env` and `frontend/.env.example` to `frontend/.env` if you need to change a setting. Everything is optional:

| Variable | File | Purpose |
|---|---|---|
| `GROQ_API_KEY`, `GROQ_API_KEY_1..4` | `backend/.env` | AI judge, explanations and chat. Keys are tried in order; the next key is used on 429 / 401 / 403 / 404. Keys of one Groq organization share one daily quota. |
| `API_KEY` | `backend/.env` | When set, every `/api` request must send it as an `X-API-Key` header or gets 401. Empty (default) = no key, as the demo runs. The frontend does not send this header yet, so the UI stops working when it is set. |
| `CORS_ORIGINS` | `backend/.env` | Origins allowed to call the API: `*` (default) or a comma-separated list. |
| `ADAPTIVE_DB_PATH` | `backend/.env` | SQLite database for recognizers, learned mappings, rejected lines and the AI judge cache. Default `backend/data/adaptive.db`. |
| `DATABASE_URL` | `backend/.env` | Postgres (e.g. a Supabase Session pooler URI) instead of the SQLite file, for hosts whose disk is wiped on restart. Empty (default) = SQLite. Tests always use SQLite. |
| `AI_JUDGE_MAX_CALLS_PER_SCAN` | `backend/.env` | AI judge requests per scan (default 2; cache hits are free). |
| `VENDOR_PARSE_COVERAGE_THRESHOLD` | `backend/.env` | Share of lines that must follow the detected vendor's grammar (default 0.7). |
| `ADAPTIVE_AI_FOR_KNOWN_VENDORS` | `backend/.env` | Legacy, default `false`: send lines the Cisco / FortiGate parsers do not read to the line interpreter; results only reach the review queue. |
| `LIVE_COLLECTION_ENABLED` | `backend/.env` | Pull configurations off devices over SSH (default `true`). Set `false` on any backend others can reach: the endpoint opens a session to whatever host it is given. |
| `LIVE_COLLECTION_NETWORKS` | `backend/.env` | Where collection may connect (default `private`): the host is resolved and refused unless it is RFC1918 or loopback, with link-local refused by name because that is the cloud metadata endpoint. `any` lifts it. |
| `VITE_API_BASE_URL` | `frontend/.env` | Backend URL, default `http://localhost:8000/api`. |

## Testing

```bash
cd backend
venv\Scripts\python -m pytest tests -q -n auto   # 1588 passed, 2 skipped (live AI, needs NETAUDIT_LIVE_AI=1)

cd frontend
npm test                                    # 149 passed
npm run build
```

Every AI call is mocked and every test gets its own SQLite database. See [docs/testing.md](docs/testing.md).

## Persistence

The three knowledge tables live in SQLite (`ADAPTIVE_DB_PATH`) by default, or in Postgres when `DATABASE_URL` is
set. Same schema and SQL on both; Postgres connections are pooled and reads are cached per process.

| Data | Where | Survives restart |
|---|---|---|
| Confirmed recognizers and learned mappings | `learned_mappings` | Yes -reused by every later scan and process |
| Lines an administrator rejected | `rejected_lines`, stored redacted | Yes |
| Verified AI judge answers | `ai_judge_cache` (answers to redacted prompts) | Yes |
| Scan results, uploaded configurations | Backend memory | No |
| Scan history in the UI | Browser `localStorage`: summaries only (no findings, evidence or config lines) | Browser only; reopening needs the backend to still hold the scan |

A line holding a secret (password, key, community string) is never stored as a mapping or recognizer.

## Known limitations

- Prototype, not a production security tool. Access control is one optional shared `API_KEY`: no users, no roles. With the defaults the API is open and CORS allows every origin.
- Parsers cover common Cisco IOS and FortiGate syntax; the IOS grammar is a curated root list, so an unusual real IOS config can come out unverified.
- 23 controls. Remediation recipes exist only for Cisco IOS and FortiGate; weak stored passwords, AAA without a strong local account and any-to-any rules always need a human.
- Unknown vendors rely on lexicon heuristics and confirmed recognizers; heuristics can misread a dialect until an administrator confirms or rejects the line.
- Shipped seed knowledge covers eleven dialects, AWS / Azure / GCP exports and Terraform, 226 recognizers, so it answers only part of each dialect. Everything it does not cover still has to be taught, and a dialect with no seeds behaves exactly as before.
- Redaction is pattern-based: a secret behind an unlisted keyword could still reach the AI.
- The AI judge escalates only unknown / unverified vendors; UNKNOWN controls of confirmed vendors are not sent to AI.
- Scan results live in memory; recognizer replay only checks scans held by the running backend. A candidate remediation lives in its scan only and is never persisted as knowledge.
- A candidate can only be verified when it explicitly removes or switches off the lines the finding cites; anything else is kept for review as unverified.
- Framework views cover NIST SP 800-53 Rev. 5, verified CIS items, the DISA Network Device Management SRG and ISO/IEC 27001:2022 Annex A (no PCI DSS or CIS Controls v8 mappings).
- `/api/assistant/status` reports AI available whenever a key is configured, even if the quota is used up.
- Live collection **reads** a device (one SSH session, read-only commands, credentials never stored) and is bounded to private address space by default. No command, generated or proposed, is ever executed on a device.

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture-brief.pdf](docs/architecture-brief.pdf) | Two-page architecture brief (evaluation deliverable), generated from [the Markdown](docs/architecture-brief.md) by `python backend/scripts/build_architecture_pdf.py` |
| [docs/architecture.md](docs/architecture.md) | Pipeline, vendors, facts, controls, scoring, AI, recognizers, persistence, remediation, frameworks |
| [docs/security-model.md](docs/security-model.md) | Trust boundaries and safety guarantees |
| [docs/ai-design.md](docs/ai-design.md) | AI judge, remediation candidates, verification, cache, legacy interpreter |
| [docs/api.md](docs/api.md) | Endpoints and response fields |
| [docs/policy.md](docs/policy.md) | Organisation policy: your own stricter baseline and approved servers |
| [docs/cli.md](docs/cli.md) | Command line for CI pipelines (exit codes, SARIF, GitHub Actions) |
| [docs/detection-rules.md](docs/detection-rules.md) | The 23 controls, per-vendor facts and remediation |
| [docs/data-model.md](docs/data-model.md) | Core objects |
| [docs/seed-knowledge.md](docs/seed-knowledge.md) | Shipped recognizers: what they are, how they load, how to add one |
| [docs/demo.md](docs/demo.md) | SIH demo script |
| [docs/setup.md](docs/setup.md), [docs/testing.md](docs/testing.md), [docs/deployment.md](docs/deployment.md) | Running and testing |
