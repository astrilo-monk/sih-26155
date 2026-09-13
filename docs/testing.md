# Testing Strategy

The backend uses `pytest`; the frontend uses Vitest with Testing Library. No test needs network access or an API key: every AI call is mocked, and each backend test gets its own temporary SQLite database (`backend/tests/conftest.py`).

## Backend

| Area | Tests |
|------|-------|
| Parsers, rules, scoring | `test_pipeline.py`, `test_cisco_acl.py`. Fixture configs in `backend/tests/fixtures/` |
| Remediation | `test_remediation_e2e.py`, `test_download_fixed.py`. Verified fixes pass on a real rescan, nothing regresses, output is idempotent, unsafe / unverified cases are never reported fixed |
| Settings | `test_config_loading.py` |
| Adaptive capture and relevance filter | `test_adaptive.py`, `test_adaptive_api_integration.py` |
| Confidence tiers and evidence validation | `test_phase3_adaptive_mapper.py`, `test_phase3_e2e.py` |
| Training review API | `test_phase4_review_api.py` |
| Learned mappings (SQLite) | `test_phase5_learned_mappings.py` |
| Scan → confirm → rescan with no AI call | `test_phase6_adaptive_e2e.py` |
| Vendor-agnostic pipeline over four unrelated syntaxes | `test_adaptive_generic.py` |
| Groq API-key rotation | `test_ai_client_key_rotation.py` |

`test_adaptive_generic.py` also contains live Groq tests. They are skipped unless `NETAUDIT_LIVE_AI=1` is set and a key is configured.

## Frontend

| Area | Tests |
|------|-------|
| Training tab (review queue, AI-unavailable state, vendor evidence) | `src/components/AdaptiveTraining.test.jsx` |
| Client-side mapping validation | `src/utils/adaptiveValidation.test.js` |

## Run the Tests

```powershell
cd backend
pytest tests/ -q

cd ../frontend
npm test
npm run build
```
