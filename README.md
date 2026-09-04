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

### What's in progress
- Wider parser coverage and stronger automated tests
- Persistent scan storage

### What's planned
- Palo Alto support
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

See [docs/architecture.md](docs/architecture.md) for the full architecture.

## Tech Stack

- **Backend**: Python 3.11+ / FastAPI
- **Frontend**: React (Vite)
- **Storage**: In-memory scan store for the prototype
- **AI**: Google Gemini API
- **Testing**: pytest

See [docs/decisions.md](docs/decisions.md) for why we chose these.

## Setup

### Prerequisites
- Python 3.11+
- Node.js 18+
- Google Gemini API key (for AI features — optional, the tool works without it)

### Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate    # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Environment
Create a `.env` file in the `backend/` directory:
```
GEMINI_API_KEY=your_key_here   # optional
```

## Testing
```bash
cd backend
pytest tests/ -v
```

## Supported Vendors

| Vendor | Format | Status |
|--------|--------|--------|
| Cisco IOS/IOS-XE | CLI text (`show running-config`) | Implemented for common patterns |
| Fortinet FortiGate | Block CLI (`config/edit/set/end`) | Implemented for common patterns |
| Palo Alto PAN-OS | XML | Planned (stretch goal) |

## Known Limitations

- This is a hackathon prototype, not a production security tool
- Parsers handle common config patterns but won't cover every edge case
- AI explanations are optional and should be reviewed, not blindly trusted
- Remediation operates on copies — it never modifies real configs
- Scan results are stored only in memory and disappear when the backend restarts
- Scanned PDF/image configs are not supported (text configs only)
- No live device connections — upload-only

## Project

- **Problem**: SIH26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor
- **Sponsor**: NTRO (National Technical Research Organisation)
- **Theme**: Cybersecurity
- **Hackathon**: Smart India Hackathon 2026

## Documentation

See the [docs/](docs/) directory for detailed documentation.
