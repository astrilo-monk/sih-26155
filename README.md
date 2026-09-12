# NetAuditAI

AI-driven multi-vendor network security compliance auditor. Built for Smart India Hackathon 2026 (SIH26155).

## What This Does

Upload network device configuration files (Cisco IOS, Fortinet FortiGate), and the system will:

1. Auto-detect the vendor
2. Parse the configuration
3. Run 15 security checks against it
4. Show a security score with findings by severity
5. Explain each finding with evidence from the actual config
6. Generate vendor-specific fix commands
7. Let you verify the fix by re-analyzing the patched config
8. Map findings to CIS Benchmarks and NIST 800-53 controls

## Current Status

**Working hackathon prototype.** See [docs/project-overview.md](docs/project-overview.md) for the current implementation and [docs/roadmap.md](docs/roadmap.md) for next steps.

### What works
- Cisco IOS and FortiGate parsers
- Shared normalized configuration model
- 15 deterministic security rules
- Security scoring, evidence, and compliance mappings
- Remediation templates and before/after verification
- React/Vite dashboard
- Adaptive parsing for unknown vendors and unfamiliar syntax: relevance filter
  → learned mappings → batched AI interpretation into a fixed field vocabulary
  → evidence validation and confidence tiers → admin Training tab → confirmed
  mappings persisted in SQLite

### What's in progress
- Wider parser coverage and stronger automated tests
- Persistent scan storage

### What's planned
- Vendor-neutral control catalog (CIS / NIST / STIG / ISO) so unknown vendors
  are checked by more than the vendor-neutral rules
- PDF reports and historical scan comparisons

## Architecture

```
Upload config → Auto-detect vendor → Parse → Normalize → Analyze → Score → Dashboard
                                                                         ↓
                                                                    AI explains
                                                                         ↓
                                                                   Generate fix
                                                                         ↓
                                                                  Re-analyze → Compare
```

Lines a parser does not understand (and every line of an unknown-vendor
config) go through the adaptive layer before analysis:

```
Unrecognized line (with its block path, e.g. "config system > edit admin")
  → not security-relevant?        → ignored
  → previously rejected?          → skip (never re-sent to AI)
  → confirmed learned mapping?    → normalize, no AI call
  → AI interpretation (Groq, 10 lines per request, fixed field vocabulary)
      → evidence check: cited text is in the line, value present, on/off polarity
      → HIGH confidence + valid evidence  → auto-map
      → MEDIUM / LOW / contradicted       → Training queue
      → AI unavailable (no key, quota)    → Training queue, marked "AI unavailable"
  → admin accept / edit           → mapping saved to SQLite, config re-analyzed
```

The deterministic rules stay the only compliance authority. The system does
not retrain the AI model; it learns by persisting administrator-confirmed
syntax-to-concept mappings.

For configs no parser recognizes, `device.vendor` stays `unknown`. The AI's
view of the likely vendor is reported separately as *vendor evidence* and is
never used to switch on vendor-specific rules.

The list of fields the AI may map to lives in one place,
`backend/app/models/field_catalog.py`, and drives the AI schema, the prompt,
validation and the Training tab dropdown.

See [docs/architecture.md](docs/architecture.md) for the full architecture.

## Tech Stack

- **Backend**: Python 3.11+ / FastAPI
- **Frontend**: React (Vite)
- **Storage**: In-memory scan store; SQLite for learned adaptive mappings
- **AI**: Groq API (structured JSON output)
- **Testing**: pytest (backend), Vitest + Testing Library (frontend)

See [docs/decisions.md](docs/decisions.md) for why we chose these.

## Setup

### Prerequisites
- Python 3.11+
- Node.js 18+
- Groq API key (for AI features — optional, the tool works without it)

### Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate    # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Environment
Copy the example files and fill in what you need:
```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

| Variable | File | Purpose |
|----------|------|---------|
| `GROQ_API_KEY`, `GROQ_API_KEY_1..4` | `backend/.env` | Optional. Keys are tried in order; the next key is used on a rate limit (429) or key rejection (401/403/404). Keys in the same Groq organization share one daily quota. |
| `ADAPTIVE_DB_PATH` | `backend/.env` | Optional. Learned-mapping database, default `backend/data/adaptive.db`. |
| `ADAPTIVE_AI_FOR_KNOWN_VENDORS` | `backend/.env` | Optional, default `false`. Also send unparsed Cisco/FortiGate lines to the AI. |
| `VITE_API_BASE_URL` | `frontend/.env` | Backend URL, default `http://localhost:8000/api`. Change it if uvicorn runs on another port. |

## Testing
```bash
cd backend
pytest tests/ -v

cd frontend
npm test
npm run build
```

Backend tests use a temporary SQLite database per test and mock every AI call.
`tests/test_phase6_adaptive_e2e.py` is the end-to-end adaptive learning demo,
and `tests/test_adaptive_generic.py` runs the adaptive pipeline over four
unrelated config syntaxes. Its live Groq tests are skipped unless
`NETAUDIT_LIVE_AI=1` is set.

## Supported Vendors

| Vendor | Format | Status |
|--------|--------|--------|
| Cisco IOS/IOS-XE | CLI text (`show running-config`) | Implemented for common patterns |
| Fortinet FortiGate | Block CLI (`config/edit/set/end`) | Implemented for common patterns |
| Palo Alto PAN-OS | XML / set CLI | No parser; scanned through the adaptive layer (vendor stays `unknown`) |
| Any other vendor | Text | Scanned through the adaptive layer; score flagged provisional |

## Known Limitations

- This is a hackathon prototype, not a production security tool
- Parsers handle common config patterns but won't cover every edge case
- AI explanations are optional and should be reviewed, not blindly trusted
- Remediation operates on copies — it never modifies real configs
- Scan results are stored only in memory and disappear when the backend restarts
  (learned mappings persist in SQLite)
- Most management rules are vendor-specific; for an unknown vendor only the
  vendor-neutral rules (logging, NTP, source routing, IPsec crypto) can evaluate
  adaptively normalized values, so its score is flagged provisional
- Adaptive AI interpretation needs Groq quota; once the daily quota is used up,
  unknown-vendor lines show "AI unavailable" and must be mapped manually
- `/api/assistant/status` reports AI as available whenever a key is configured,
  even if the Groq quota is exhausted
- For Cisco configs, `/api/verify` does not yet reflect only the supplied
  commands — the preview can report more resolved findings than the fix covers
- The Training endpoints have no authentication — any client can confirm mappings
- Scanned PDF/image configs are not supported (text configs only)
- No live device connections — upload-only

## Project

- **Problem**: SIH26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor
- **Sponsor**: NTRO (National Technical Research Organisation)
- **Theme**: Cybersecurity
- **Hackathon**: Smart India Hackathon 2026

## Documentation

See the [docs/](docs/) directory for detailed documentation.
