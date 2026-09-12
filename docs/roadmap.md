# Development Roadmap

Track our hackathon progress here.

## Phase 1: Foundation (Completed)
- [x] Setup FastAPI project structure
- [x] Define Normalized Data Model (`normalized.py`)
- [x] Define Findings Model (`findings.py`)
- [x] Implement Vendor Detector (`detector.py`)
- [x] Create base parser interface (`base.py`)
- [x] Cisco IOS Parser
- [x] FortiGate Parser
- [x] Sample config fixtures for testing

## Phase 2: Core Logic (Completed for Prototype)
- [x] Security Rules Engine (Implemented 15 rules against normalized model)
- [x] Security Scoring Algorithm (Penalty based)
- [x] API endpoints (`/api/scan`, `/api/remediate`, `/api/verify`, `/api/download-fixed`, `/api/assistant/*`)
- [ ] SQLite Database Integration for saving scans (Currently using in-memory store)

## Phase 3: AI & Frontend (Completed for Prototype)
- [x] AI integration for explanations (Groq; originally Gemini)
- [x] Deterministic remediation generation
- [x] Scaffold React/Vite frontend
- [x] Upload UI and Dashboard
- [x] Findings detail view with remediation actions
- [ ] Connect the existing assistant endpoints to a frontend chat view

## Phase 4: Adaptive Parsing (Completed for Prototype)
- [x] Capture unrecognized lines with generic block context
- [x] Security relevance filter
- [x] AI interpretation into a controlled field vocabulary (`field_catalog.py`)
- [x] Evidence validation and confidence tiers
- [x] Training tab: accept / edit / reject, with AI-unavailable status
- [x] Learned mappings persisted in SQLite and reused without AI calls
- [x] Vendor evidence reported separately; AI never sets the vendor
- [x] Groq API-key rotation for rate limits and rejected keys

## Phase 5: Hardening (In Progress)
- [x] End-to-end testing with sample configs
- [x] Full Project Technical Audit
- [x] Adaptive, remediation, key-rotation and frontend tests
- [ ] Demo script rehearsal
- [ ] Bug fixing and UI polish
- [ ] Fix `/api/verify` preview for Cisco so it reflects only the supplied commands
- [ ] Make `/api/assistant/status` reflect exhausted quota
- [ ] Improve multi-file verification so it targets the selected device
- [ ] Replace in-memory scan storage with persistent storage
- [ ] Authentication for Training endpoints

## Phase 6: Towards the Full Problem Statement (Planned)
- [ ] Vendor-neutral control catalog (CIS / NIST / STIG / ISO) so unknown vendors get more than the vendor-neutral rules
- [ ] PDF reports and historical scan comparison
