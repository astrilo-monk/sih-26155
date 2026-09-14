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
| Parsers, pipeline, ACLs | `test_pipeline.py`, `test_cisco_acl.py` |
| Adaptive layer and legacy interpreter, learned mappings, review API | `test_adaptive.py`, `test_adaptive_generic.py`, `test_adaptive_api_integration.py`, `test_phase3_adaptive_mapper.py`, `test_phase3_e2e.py`, `test_phase4_review_api.py`, `test_phase5_learned_mappings.py` |
| Settings, Groq key rotation | `test_config_loading.py`, `test_ai_client_key_rotation.py` |
| Browser UI audit regressions — no secret in API responses, `config_index` identity, generic hostnames, manual-review consistency, CIS banner mapping, scan status | `test_ui_audit_regressions.py` |

Two live Groq tests in `test_adaptive_generic.py` are skipped unless `NETAUDIT_LIVE_AI=1` and a key are set.

## Frontend (`frontend/src/`)

| Area | Tests |
|---|---|
| Review queue, learned mappings, counters refreshed after a recognizer is saved, expired scan | `components/AdaptiveTraining.test.jsx` |
| Recognizer confirmation | `components/RecognizerQueue.test.jsx` |
| Remediation statuses, inputs, download only of the reviewed plan, one plan request per scan | `components/RemediationQueue.test.jsx` |
| Framework view | `components/FrameworkView.test.jsx` |
| Posture never shown as a full assessment without full coverage | `components/ScoreOverview.test.jsx` |
| Devices by `config_index`, risk from decisive findings only | `components/DeviceInfo.test.jsx` |
| Remediation targets the finding's own upload | `components/FindingDetail.test.jsx` |
| Expired history entries | `components/HistoryView.test.jsx` |
| Empty states without a scan | `App.test.jsx` |
| Summary-only history | `utils/history.test.js` |
| Mapping form validation | `utils/adaptiveValidation.test.js` |

## Run

```powershell
cd backend
venv\Scripts\python -m pytest tests -q     # 853 passed, 2 skipped

cd ..\frontend
npm test                                    # 34 passed
npm run build
```

No linter or type checker is configured in the repository.
