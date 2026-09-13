# NetAuditAI Project Overview

NetAuditAI is an AI-assisted, multi-vendor network security compliance auditor. It analyzes uploaded network device configuration files, detects security weaknesses, assigns a security score, provides evidence and compliance mappings, generates deterministic remediation commands, and verifies proposed fixes on a copy of the configuration.

The project is designed for the Smart India Hackathon 2026 cybersecurity problem SIH26155.

## What the Project Does

A user uploads one or more network configuration files. NetAuditAI then:

1. Detects the configuration vendor.
2. Parses the vendor-specific syntax.
3. Converts the result into a shared normalized data model.
4. Runs security rules against the normalized model.
5. Calculates a score from 0 to 100.
6. Displays findings with severity, evidence, impact, recommendations, and compliance references.
7. Generates vendor-specific remediation commands.
8. Applies the commands to a copy of the configuration.
9. Re-runs the analysis to show before-and-after results.

The system has parsers for Cisco IOS and FortiGate. Configurations from other vendors, and lines the parsers do not recognize, go through an adaptive layer: recognizers, learned mappings and lexicon heuristics, then an AI judge whose verified proposals stay provisional until an administrator confirms them in the Training tab. See [ai-design.md](ai-design.md).

## Architecture

```mermaid
flowchart TD
    User[User] --> Frontend[React/Vite Dashboard]
    Frontend -->|Upload files| API[FastAPI API]
    API --> Detector[Vendor Detector]
    Detector --> Cisco[Cisco IOS Parser]
    Detector --> Fortinet[FortiGate Parser]
    Detector --> Adaptive[Adaptive Layer: learned mappings + AI]
    Cisco --> Normalized[NormalizedConfig]
    Fortinet --> Normalized
    Cisco --> |Unrecognized lines| Adaptive
    Adaptive --> Normalized
    Adaptive --> Training[Training Tab + SQLite]
    Normalized --> Rules[Security Rules Engine]
    Rules --> Findings[Findings]
    Findings --> Score[Score Calculator]
    Score --> Dashboard[Dashboard Results]
    Findings --> Templates[Remediation Templates]
    Templates --> Verify[Copy, Patch, Re-analyze]
    Findings --> AI[Optional Groq Assistant]
```

The central design decision is the normalized model. Vendor-specific parsers translate different configuration syntaxes into the same `NormalizedConfig` structure. The security rules operate on that common structure, so most rules do not need separate Cisco and FortiGate implementations.

## Repository Structure

```text
backend/
  app/
    main.py                 FastAPI application and router registration
    config.py               Environment settings and upload limits
    api/
      schemas.py            Request and response models
      routes/               Scan, remediation, assistant, and adaptive training endpoints
    ai/
      client.py             Groq API wrapper (key rotation, structured output)
      prompts.py            Explanation and summary prompts
      interpretation_schemas.py  Schemas for adaptive AI interpretation
    adaptive/
      capture.py, context.py     Capture unrecognized lines with their block path
      relevance.py               Security-relevance filter
      matcher.py                 Apply confirmed learned mappings
      interpreter.py             Batched AI interpretation
      mapper.py                  Evidence validation and confidence tiers
      vendor.py                  Vendor-name normalization and vendor evidence
      service.py                 Orchestrates the adaptive pipeline
    db/
      database.py, mappings.py   SQLite store for learned mappings
    analysis/
      engine.py             Runs all security rules
      scoring.py            Calculates the security score
      rules/                Management, boundary, logging, and crypto rules
    models/
      normalized.py         Shared vendor-neutral configuration dataclasses
      field_catalog.py      Fields the adaptive layer may set (single source of truth)
      findings.py           Finding and scan result dataclasses
    parsers/
      detector.py           Cisco/FortiGate vendor detection
      cisco_ios.py          Cisco IOS parser
      fortinet.py           FortiGate parser
    remediation/
      engine.py             Deterministic fix templates and verification patching
  tests/                    Backend pipeline, parser, remediation, and adaptive tests
  .env.example              Example backend settings
frontend/
  src/
    App.jsx                 Main UI state and workflow
    api/client.js           HTTP client for backend endpoints
    components/             Dashboard, findings, remediation, comparison, and Training UI
  .env.example              Example frontend settings (VITE_API_BASE_URL)
  index.css                 Application styling
  package.json              Frontend dependencies and scripts
docs/                       Architecture, API, rules, setup, and project documentation
```

## Backend

The FastAPI application is defined in [backend/app/main.py](../backend/app/main.py). It registers four route groups under `/api`:

- Scan routes
- Remediation routes
- Assistant routes
- Adaptive training routes

CORS is currently open to all origins to simplify local development. This should be restricted before production deployment.

### Scan Processing

The main scan workflow is implemented in [backend/app/api/routes/scan.py](../backend/app/api/routes/scan.py).

For each uploaded file, the API:

- Reads the file into memory.
- Enforces a 2 MB maximum size.
- Requires valid UTF-8 text.
- Rejects empty files.
- Detects the vendor.
- Selects a parser.
- Produces a `NormalizedConfig`.

One file is analyzed with `analyze()`. Multiple files are analyzed individually and merged with `analyze_multiple()`.

Unknown-vendor configs, and lines a parser did not recognize, are then passed through the adaptive layer before analysis (see [ai-design.md](ai-design.md)).

Scan results are stored in a process-local dictionary and are not persisted. Only administrator-confirmed adaptive mappings are stored in SQLite.

### Normalized Configuration

The shared data model is defined in [backend/app/models/normalized.py](../backend/app/models/normalized.py).

`NormalizedConfig` represents:

- Device hostname, vendor, and OS version
- Interfaces and interface services
- VTY and console management lines
- SSH, HTTP, HTTPS, and Telnet access
- AAA and local users
- Password encoding types
- SNMP communities and SNMPv3 state
- Logging and remote syslog
- NTP servers and authentication
- Cisco ACLs
- FortiGate firewall policies
- VPN/IPsec proposals
- Login banners
- Global services such as IP source routing and CDP
- The original raw configuration and source line numbers

Keeping the raw lines and line numbers allows the application to show the exact configuration evidence behind each finding.

## Security Rules

There are 15 controls, declared in [backend/app/controls/catalog.py](../backend/app/controls/catalog.py). Controls read security facts, never vendor structures: vendor parsers feed facts through [backend/app/facts/from_normalized.py](../backend/app/facts/from_normalized.py), and [backend/app/controls/evaluate.py](../backend/app/controls/evaluate.py) runs every control on every config.

### Management Rules

Judged in [backend/app/controls/judges.py](../backend/app/controls/judges.py):

| Rule | Finding | Severity |
|---|---|---|
| MGMT-001 | Telnet enabled | Critical |
| MGMT-002 | Insecure HTTP management enabled | High |
| MGMT-003 | Unrestricted management access | Critical |
| MGMT-004 | Weak or default SNMP communities | High or Critical |
| MGMT-005 | Plaintext or weakly encrypted passwords | Critical |
| MGMT-006 | Missing or disabled session timeout | Medium |
| MGMT-007 | SSH version 1 or weak SSH configuration | High |
| MGMT-008 | AAA not configured | High |
| MGMT-009 | Missing login banner | Low |

Cisco facts come from VTY lines, global services, password encoding and AAA. FortiGate facts come from interface management services, admin timeout and FortiOS global settings; the FortiGate parser does not read password storage or AAA, so those controls report UNKNOWN for FortiGate. Documented FortiOS defaults ([backend/app/facts/defaults.py](../backend/app/facts/defaults.py)) decide when the configuration is silent.

### Boundary Rules

Judged in [backend/app/controls/judges.py](../backend/app/controls/judges.py):

| Rule | Finding | Severity |
|---|---|---|
| BOUNDARY-001 | Overly permissive ACL or firewall rule | Critical |
| BOUNDARY-002 | IP source routing enabled | Medium |
| BOUNDARY-003 | CDP or LLDP exposed on an external interface | Medium |

The any-any check detects Cisco rules such as `permit ip any any` and FortiGate policies that accept all sources, destinations, and services.

### Logging Rules

Judged in [backend/app/controls/judges.py](../backend/app/controls/judges.py):

| Rule | Finding | Severity |
|---|---|---|
| LOG-001 | No remote syslog server configured | High |
| LOG-002 | NTP missing or unauthenticated | Medium |

### Cryptography Rules

Judged in [backend/app/controls/judges.py](../backend/app/controls/judges.py):

| Rule | Finding | Severity |
|---|---|---|
| CRYPTO-001 | Weak VPN/IPsec cryptographic algorithms | High |

The rule flags DES, 3DES, MD5, and weak Diffie-Hellman groups 1, 2, and 5.

## Findings and Scoring

Findings are defined in [backend/app/models/findings.py](../backend/app/models/findings.py). Each finding includes:

- Rule ID and title
- Severity
- Description
- Security impact
- Recommendation
- Device and vendor
- Exact evidence lines
- Original line numbers
- CIS and NIST 800-53 compliance mappings
- Finding category
- Optional AI explanation

Scoring is implemented in [backend/app/analysis/scoring.py](../backend/app/analysis/scoring.py).

The calculation starts at 100 and subtracts penalties:

| Severity | Penalty |
|---|---:|
| Critical | 12 |
| High | 6 |
| Medium | 3 |
| Low | 1 |

The score cannot fall below zero.

## API Endpoints

API request and response schemas are defined in [backend/app/api/schemas.py](../backend/app/api/schemas.py).

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Check whether the backend is running |
| POST | `/api/scan` | Upload and analyze one or more configurations |
| GET | `/api/scan/{scan_id}` | Retrieve an in-memory scan result |
| POST | `/api/remediate` | Generate remediation commands for a finding |
| POST | `/api/verify` | Apply commands to a copy and re-analyze it |
| POST | `/api/download-fixed` | Download fully remediated configs |
| POST | `/api/assistant/chat` | Ask the AI about a scan |
| GET | `/api/assistant/explain/{scan_id}/{rule_id}/{hostname}` | Generate a finding explanation |
| GET | `/api/assistant/summary/{scan_id}` | Generate a scan summary |
| GET | `/api/assistant/status` | Check whether AI is configured |
| GET | `/api/adaptive/fields` | Normalized fields available for mapping |
| GET | `/api/adaptive/scans/{scan_id}/review` | Training review queue |
| POST | `/api/adaptive/scans/{scan_id}/review/{item_id}/accept` \| `edit` \| `reject` | Review an interpretation |
| GET / PATCH / DELETE | `/api/adaptive/mappings[/{mapping_id}]` | Manage learned mappings |

Full request and response details are in [api.md](api.md).

## Remediation

Remediation is implemented in [backend/app/remediation/engine.py](../backend/app/remediation/engine.py).

The system uses deterministic templates selected by rule ID and vendor. The engine has been rewritten as a comprehensive multi-phase remediation engine that handles text replacements, line removals, config additions, vendor-specific transformations, and global-service fixes. It is rule-driven, generic across Cisco IOS and FortiGate, and idempotent.

Examples include:

```text
no ip http server
ip http secure-server
```

```text
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
```

The generated commands are never applied to a real device. Verification modifies a copy of the original text and re-runs the parser and rules engine.

## Optional AI Assistant

Groq integration is implemented in [backend/app/ai/client.py](../backend/app/ai/client.py). It is enabled by setting `GROQ_API_KEY` (and optionally `GROQ_API_KEY_1` .. `_4`) in `backend/.env`.

Without an API key:

- The scanner still works.
- Finding explanations fall back to static recommendations.
- Scan summaries use static text.
- Chat reports that AI is not configured.
- Adaptive lines are marked "AI unavailable". Confirmed learned mappings still apply.

With an API key, the AI can provide:

- Plain-language explanations of findings
- Executive scan summaries
- Chat answers using scan context
- Interpretation of unfamiliar configuration lines into normalized fields, validated before use

The AI does not generate remediation commands, decide findings, or set the device vendor.

## Frontend

The main frontend workflow is controlled by [frontend/src/App.jsx](../frontend/src/App.jsx).

The interface provides:

- Drag-and-drop configuration upload
- Multi-file selection
- Loading progress display
- Security score dashboard
- Severity counts and distribution
- Device inventory
- Findings table
- Search and filtering by severity, device, and rule
- Finding detail drawer
- Configuration evidence display
- Compliance mapping display
- Remediation command drawer
- Copy-to-clipboard actions
- Before-and-after verification results
- Training tab for reviewing adaptive interpretations, including AI-unavailable lines, block paths and vendor evidence

The frontend API client is [frontend/src/api/client.js](../frontend/src/api/client.js). Its default backend URL is:

```text
http://localhost:8000/api
```

This can be overridden with the `VITE_API_BASE_URL` environment variable in `frontend/.env` (see `frontend/.env.example`).

The Remediation Queue now displays all severity groups (critical, high, medium, low) and supports bulk fixed-config download with full end-to-end verification.

## Local Setup

### Requirements

- Python 3.11 or newer
- Node.js 18 or newer
- Groq API key only if AI features are required

### Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

The Vite frontend normally runs at `http://localhost:5173`.

### Environment

Copy the example files and fill in what you need:

```powershell
copy backend\.env.example backend\.env
copy frontend\.env.example frontend\.env
```

See [setup.md](setup.md) for what each setting does.

## Testing

Backend tests live in [backend/tests/](../backend/tests/) and frontend tests next to their components. They cover:

- Cisco and FortiGate vendor detection and parsing
- Vulnerable and secure configuration detection, scoring, Cisco ACLs
- Remediation end-to-end (fixed configs re-scan to 100/100) and fixed-config download
- The adaptive pipeline: capture, relevance, evidence validation, confidence tiers, Training API, learned mappings, and four unrelated config syntaxes
- Groq key rotation
- The Training tab UI

Run them with:

```powershell
cd backend
pytest tests/ -q

cd ..\frontend
npm test
npm run build
```

All AI calls are mocked, so no key is needed. See [testing.md](testing.md).

## Current Limitations

- Scan data is lost when the backend restarts.
- The in-memory store is unsuitable for multiple production workers.
- Vendor detection is heuristic.
- Parsers cover common syntax, not every vendor configuration edge case.
- Remediation uses a comprehensive multi-phase transformation engine
- Multi-file verification currently analyzes the first uploaded configuration.
- AI can produce incorrect explanations and should be reviewed.
- There are no live device connections.
- PDF and image configurations are unsupported.
- There is no dedicated Palo Alto parser. Such configs are scanned through the adaptive layer.
- Unknown-vendor configs are evaluated mainly by vendor-neutral rules, and their scores are flagged provisional.
- Adaptive AI interpretation depends on Groq quota. Keys in one organization share a daily limit.
- `/api/assistant/status` does not detect an exhausted quota.
- For Cisco configs, the `/api/verify` preview does not yet reflect only the supplied commands.
- Training endpoints have no authentication.
- Extensive FortiGate behavior has limited automated coverage.
- CORS is permissive for development.

## Current Status

The core prototype is functional:

- Cisco and FortiGate parsers are implemented.
- The normalized data model is implemented.
- Fifteen deterministic security rules are implemented.
- Scoring and compliance mappings are implemented.
- Remediation templates and before/after verification are implemented.
- The React dashboard is implemented.
- Optional Groq AI support is implemented.
- The adaptive layer (learned mappings, AI interpretation, evidence validation, Training tab, SQLite persistence) is implemented.

The main next steps are persistence, stronger parser coverage, robust vendor-aware remediation, correct multi-device verification, frontend AI integration, production security hardening, and broader automated tests.

- End-to-end remediation regression tests (`backend/tests/test_remediation_e2e.py`) verify that fixed configs re-scan to 100/100.

## Source of Truth

Some older documents still describe the project as planned or incomplete. The current implementation and tests are more reliable than those descriptions. In particular:

- [backend/app/](../backend/app/) describes the actual backend behavior.
- [frontend/src/](../frontend/src/) describes the actual UI behavior.
- [docs/detection-rules.md](detection-rules.md) is the closest rules reference.
- [docs/project-audit.md](project-audit.md) records known implementation and documentation issues.
