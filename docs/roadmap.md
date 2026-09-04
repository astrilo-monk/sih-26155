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
- [x] API endpoints (`/api/scan`, `/api/remediate`, `/api/verify`, and `/api/assistant/*`)
- [ ] SQLite Database Integration for saving scans (Currently using in-memory store)

## Phase 3: AI & Frontend (Completed for Prototype)
- [x] Gemini API integration for explanations
- [x] Deterministic remediation generation
- [x] Scaffold React/Vite frontend
- [x] Upload UI and Dashboard
- [x] Findings detail view with remediation actions
- [ ] Connect the existing assistant endpoints to a frontend chat view

## Phase 4: Hardening (In Progress)
- [x] End-to-end testing with sample configs
- [x] Full Project Technical Audit
- [ ] Demo script rehearsal
- [ ] Bug fixing and UI polish
- [ ] Add API, remediation, Gemini, and frontend tests
- [ ] Improve multi-file verification so it targets the selected device
- [ ] Replace in-memory storage with persistent storage
