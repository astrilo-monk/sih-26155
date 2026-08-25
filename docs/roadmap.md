# Development Roadmap

Track our hackathon progress here.

## Phase 1: Foundation (In Progress)
- [x] Setup FastAPI project structure
- [x] Define Normalized Data Model (`normalized.py`)
- [x] Define Findings Model (`findings.py`)
- [x] Implement Vendor Detector (`detector.py`)
- [x] Create base parser interface (`base.py`)
- [ ] Cisco IOS Parser
- [ ] FortiGate Parser
- [ ] Sample config fixtures for testing

## Phase 2: Core Logic (Planned)
- [ ] Security Rules Engine (Implement 15 rules against normalized model)
- [ ] Security Scoring Algorithm (Penalty based)
- [ ] API endpoints (`/scan`, `/findings`)
- [ ] SQLite Database Integration for saving scans

## Phase 3: AI & Frontend (Planned)
- [ ] Gemini API integration for explanations
- [ ] Gemini API integration for remediation generation
- [ ] Scaffold React/Vite frontend
- [ ] Upload UI and Dashboard
- [ ] Findings detail view with AI chat

## Phase 4: Polish (Planned)
- [ ] End-to-end testing with sample configs
- [ ] Demo script rehearsal
- [ ] Bug fixing and UI polish
