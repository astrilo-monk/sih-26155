# Testing

Backend tests use `pytest`; frontend tests use Vitest with Testing Library. No test needs a network or an API key:
the AI judge transport is patched in every test (`backend/tests/conftest.py`), and each test gets its own temporary
SQLite database.

## Backend (`backend/tests/`)

| Area | Tests |
|---|---|
| Phase 0 — golden findings snapshots for 30 Cisco / FortiGate configs | `test_phase0_snapshots.py` |
| Phase 1 — redaction, vendor identification and look-alikes, honest unknowns | `test_phase1_redaction.py`, `test_phase1_vendor_identification.py`, `test_phase1_honest_unknowns.py` |
| Phase 2 — control catalog, NIST / CIS mappings, ControlResult | `test_phase2_controls.py` |
| Phase 3 — posture and coverage | `test_scoring_v2.py` |
| Phase 4 — security facts, decision tables, defaults | `test_phase4_facts.py` |
| Phase 5 — tokenizer and lexicon heuristics (`sample/unknown.cfg` acceptance) | `test_phase5_heuristics.py` |
| Phase 6 — recognizers, gates, replay, Training API | `test_phase6_recognizers.py`, `test_phase6_adaptive_e2e.py` |
| Phase 7 — AI judge: verifier, budget, cache, redaction, authority | `test_phase7_ai_judge.py` |
| Phase 8 — remediation: recipes, inputs, verification, idempotence, API rescan | `test_remediation_e2e.py`, `test_download_fixed.py` |
| Phase 9 — framework views, recognizer persistence across a restart, secret-free stores | `test_phase9_frameworks_persistence.py` |
| Candidate remediation for unconfirmed vendors: eligibility, validation, simulation on a copy, verified / rejected / unverified, human confirmation, AI answer shape and prompt redaction, no vendor branch | `test_candidate_remediation.py` |
| Generic engine on hierarchical, terminator-separated dialects | `test_generic_hierarchical.py` |
| Parsers, pipeline, ACLs | `test_pipeline.py`, `test_cisco_acl.py` |
| Adaptive layer and legacy interpreter, learned mappings, review API | `test_adaptive.py`, `test_adaptive_generic.py`, `test_adaptive_api_integration.py`, `test_phase3_adaptive_mapper.py`, `test_phase3_e2e.py`, `test_phase4_review_api.py`, `test_phase5_learned_mappings.py` |
| Settings, Groq key rotation | `test_config_loading.py`, `test_ai_client_key_rotation.py` |
| Browser UI audit regressions — no secret in API responses, `config_index` identity, generic hostnames, manual-review consistency, CIS banner mapping, scan status | `test_ui_audit_regressions.py` |

Two live Groq tests in `test_adaptive_generic.py` are skipped unless `NETAUDIT_LIVE_AI=1` and a key are set.

## Frontend (`frontend/src/`)

| Area | Tests |
|---|---|
| Backend state to user-facing state, counts, next step, plain-language readings, safety-gate wording | `lib/domain.test.js` |
| Results overview: posture never overstated, honest counts, questions, undecided checks | `app/Results.test.jsx` |
| Fix: the remediation classes, inputs, verified fix, download of verified changes only, and candidate remediation for an unconfirmed vendor (generate, review, verify, reject, confirm) | `app/Fix.test.jsx` |
| Teach: plain meaning questions, safety-gate failures in plain English, saved recognizer | `app/Teach.test.jsx` |
| Finding drawer: evidence, assurance, no invented commands | `app/FindingDrawer.test.jsx` |
| Framework view | `app/Frameworks.test.jsx` |
| Expired history entries | `app/History.test.jsx` |
| Legacy review queue | `app/LegacyInterpretations.test.jsx` |
| Homepage claims, entering the application, expired scan | `App.test.jsx` |
| Shared hooks (reveal, sequence, reduced motion) | `lib/hooks.test.jsx` |
| Evidence and status primitives | `components/ui/ui.test.jsx` |
| Summary-only history | `utils/history.test.js` |
| Mapping form validation | `utils/adaptiveValidation.test.js` |

## Run

```powershell
cd backend
venv\Scripts\python -m pytest tests -q     # 924 passed, 2 skipped

cd ..\frontend
npm test                                    # 70 passed
npm run build
```

No linter or type checker is configured in the repository.
