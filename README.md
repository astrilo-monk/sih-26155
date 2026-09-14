# NetAuditAI

Configuration security auditor for network devices, built for Smart India Hackathon 2026
(SIH26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor, NTRO, Cybersecurity).

NetAuditAI answers 15 security questions (**controls**) about every uploaded configuration, cites the
configuration lines behind every answer, keeps what it could decide separate from what it could not, and
fixes confirmed Cisco / FortiGate findings with deterministic changes that are verified by a rescan.
AI is optional: it only proposes answers for controls the deterministic engine left undecided, and a
human confirms them before they count.

## Status

Working hackathon prototype. All phases of [plan.md](plan.md) (0–9) are implemented. Backend: 834 tests
passed, 2 live-AI tests skipped. Frontend: 19 tests passed, production build OK.

## Pipeline

```text
Raw configuration (read into memory, never written to disk)
  ↓
Vendor detection + parse coverage ..................... app/parsers/detector.py, coverage.py
  ↓ confirmed Cisco IOS / FortiGate            ↓ unknown or unverified vendor
Dedicated parser → PARSER facts               Generic tokenizer ......... app/structure/tokenizer.py
+ documented vendor defaults → DEFAULT          → confirmed recognizers → CONFIRMED facts
                                                → lexicon heuristics  → HEURISTIC facts (provisional)
  ↓
SecurityFacts: predicate, value, scope, cited lines, assurance ...... app/facts/
  ↓
Control evaluation: every control on every configuration ............ app/controls/
  ↓
Posture + coverage .................................................. app/analysis/scoring.py
  ↓ UNKNOWN / NOT_CONFIGURED controls (unknown vendors only)
AI judge: budgeted, redacted, cached (optional) ..................... app/ai/judge.py
  ↓
Deterministic citation verification → AI_VERIFIED proposal (never scored)
  ↓
Human confirmation ("Review & Recognizers") → recognizer saved in SQLite
  ↓
Future scans: the recognizer answers decisively, with no AI call
  ↓ decisive FAIL on a confirmed vendor
Deterministic remediation → re-parse → re-verify .................... app/remediation/
```

Details: [docs/architecture.md](docs/architecture.md).

## Vendor support

| Configuration | How it is analyzed | Assurance | Remediation |
|---|---|---|---|
| Cisco IOS / IOS-XE (common patterns) | Dedicated parser, confirmed by grammar coverage | Decisive (parser facts; no Cisco defaults are assumed) | Deterministic, verified |
| Fortinet FortiGate (FortiOS with a `config firewall` / `config vpn` section) | Dedicated parser, confirmed by grammar coverage | Decisive; password storage and AAA are not read by the parser (UNKNOWN) | Deterministic, verified |
| Look-alikes (Arista EOS, NX-OS, IOS-XR, ASA, Dell OS10, Brocade, FortiSwitch) and mixed configs | Reported **unverified**, then the generic path | Provisional unless a recognizer is confirmed | Blocked |
| Palo Alto, Juniper and every other vendor | **No dedicated parser.** Generic tokenizer, lexicon heuristics, confirmed recognizers, optional AI judge | Provisional; decisive only through confirmed recognizers | Blocked |

The vendor is decided deterministically. An AI vendor guess is reported as evidence only and never selects a parser, defaults or remediation.

## Reading the results

- **Status** per control: `PASS`, `FAIL`, `UNKNOWN` (something relevant exists but could not be decided), `NOT_CONFIGURED` (nothing relevant found — never counted as PASS), `N_A`.
- **Assurance**: `parser`, `confirmed` (recognizer or administrator mapping) and `default` (documented vendor default) are **decisive**; `heuristic` and `ai_verified` are **provisional** ("Suspected FAIL", "Probable PASS", "AI proposes …").
- **Posture** = weighted PASS ÷ (PASS + FAIL) over decisive results; "—" when nothing was decided.
- **Coverage** = weighted share of applicable controls decided decisively. Posture and coverage are shown side by side, with the posture range if every undecided control failed or passed.
- **Critical not assessed** lists critical controls that were not decided.
- Provisional verdicts are shown with their evidence but never change posture, coverage, findings counts or remediation.
- **Framework views** regroup the same results under NIST SP 800-53 Rev. 5 and, for confirmed vendors, CIS Benchmarks. They are not a compliance certification.

The scan response still carries `score`, the deprecated penalty score (kept for existing scripts). The UI does not use it.

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
| `ADAPTIVE_DB_PATH` | `backend/.env` | SQLite database for recognizers, learned mappings, rejected lines and the AI judge cache. Default `backend/data/adaptive.db`. |
| `AI_JUDGE_MAX_CALLS_PER_SCAN` | `backend/.env` | AI judge requests per scan (default 2; cache hits are free). |
| `VENDOR_PARSE_COVERAGE_THRESHOLD` | `backend/.env` | Share of lines that must follow the detected vendor's grammar (default 0.7). |
| `ADAPTIVE_AI_FOR_KNOWN_VENDORS` | `backend/.env` | Legacy, default `false`: send lines the Cisco / FortiGate parsers do not read to the line interpreter; results only reach the review queue. |
| `VITE_API_BASE_URL` | `frontend/.env` | Backend URL, default `http://localhost:8000/api`. |

## Testing

```bash
cd backend
venv\Scripts\python -m pytest tests -q     # 834 passed, 2 skipped (live AI, needs NETAUDIT_LIVE_AI=1)

cd frontend
npm test                                    # 19 passed
npm run build
```

Every AI call is mocked and every test gets its own SQLite database. See [docs/testing.md](docs/testing.md).

## Persistence

| Data | Where | Survives restart |
|---|---|---|
| Confirmed recognizers and learned mappings | SQLite `learned_mappings` | Yes — reused by every later scan and process |
| Lines an administrator rejected | SQLite `rejected_lines`, stored redacted | Yes |
| Verified AI judge answers | SQLite `ai_judge_cache` (answers to redacted prompts) | Yes |
| Scan results, uploaded configurations | Backend memory | No |
| Scan history in the UI | Browser `localStorage`: summaries only (no findings, evidence or config lines) | Browser only; reopening needs the backend to still hold the scan |

A line holding a secret (password, key, community string) is never stored as a mapping or recognizer.

## Known limitations

- Prototype, not a production security tool. No authentication on any endpoint; CORS is open.
- Parsers cover common Cisco IOS and FortiGate syntax; the IOS grammar is a curated root list, so an unusual real IOS config can come out unverified.
- 15 controls. Remediation recipes exist only for Cisco IOS and FortiGate; weak stored passwords, AAA without a strong local account and any-to-any rules always need a human.
- Unknown vendors rely on lexicon heuristics and confirmed recognizers; heuristics can misread a dialect until an administrator confirms or rejects the line.
- Redaction is pattern-based: a secret behind an unlisted keyword could still reach the AI.
- The AI judge escalates only unknown / unverified vendors; UNKNOWN controls of confirmed vendors are not sent to AI.
- Scan results live in memory; recognizer replay only checks scans held by the running backend.
- Framework views cover NIST SP 800-53 Rev. 5 and verified CIS items only (no ISO 27001, DISA SRG or CIS Controls v8 mappings).
- `/api/assistant/status` reports AI available whenever a key is configured, even if the quota is used up.
- Text configurations only; no live device connections.

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Pipeline, vendors, facts, controls, scoring, AI, recognizers, persistence, remediation, frameworks |
| [docs/security-model.md](docs/security-model.md) | Trust boundaries and safety guarantees |
| [docs/ai-design.md](docs/ai-design.md) | AI judge, verification, cache, legacy interpreter |
| [docs/api.md](docs/api.md) | Endpoints and response fields |
| [docs/detection-rules.md](docs/detection-rules.md) | The 15 controls, per-vendor facts and remediation |
| [docs/data-model.md](docs/data-model.md) | Core objects |
| [docs/demo.md](docs/demo.md) | SIH demo script |
| [docs/setup.md](docs/setup.md), [docs/testing.md](docs/testing.md), [docs/deployment.md](docs/deployment.md) | Running and testing |
| [plan.md](plan.md) | Phase-by-phase implementation record |
