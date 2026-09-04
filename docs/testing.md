# Testing Strategy

The backend has a working pytest suite. The frontend does not have automated tests yet.

Since the parsers use regular expressions and the rules make security decisions, fixture-based tests are important. The current tests use `pytest` and sample Cisco and FortiGate configurations.

## 1. Parser Testing (Fixture-based)
The current fixtures are in `backend/tests/fixtures/`. Tests run both parsers and assert important fields such as vendor, hostname, and raw lines.

## 2. Rule Testing
The pipeline tests analyze vulnerable and secure fixtures and check that the expected findings and scores are produced. Cisco ACL tests also check extended ACL parsing and `BOUNDARY-001`.

## 3. Scoring Testing
The scoring test checks the 100-point penalty calculation. The score starts at 100 and is bounded at zero.

## 4. AI Mocking
Gemini mocking and frontend tests are still future work. The current backend tests do not require a Gemini API key.

## Run the Tests

```powershell
cd backend
pytest tests/ -v
```

The current suite contains 12 passing tests.
