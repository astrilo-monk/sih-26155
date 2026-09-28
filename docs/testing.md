# Testing

Backend tests use `pytest`; frontend tests use Vitest with Testing Library. No test needs a network or an API key:
the AI judge transport is patched in every test (`backend/tests/conftest.py`), and each test gets its own temporary
SQLite database, even when `DATABASE_URL` is set. That database is empty by default -**including of the shipped seed recognizers** -so the rest of
the suite keeps proving what the generic engine works out on its own. Tests about seed knowledge ask for the
production default with the `seeded_adaptive_db` fixture.

## Backend (`backend/tests/`)

| Area | Tests |
|---|---|
| Phase 0 -golden findings snapshots for 30 Cisco / FortiGate configs | `test_phase0_snapshots.py` |
| Phase 1 -redaction, vendor identification and look-alikes, honest unknowns | `test_phase1_redaction.py`, `test_phase1_vendor_identification.py`, `test_phase1_honest_unknowns.py` |
| Phase 2 -control catalog, NIST / CIS mappings, ControlResult | `test_phase2_controls.py` |
| Phase 3 -posture and coverage | `test_scoring_v2.py` |
| Phase 4 -security facts, decision tables, defaults | `test_phase4_facts.py` |
| Phase 5 -tokenizer and lexicon heuristics (`sample/unknown.cfg` acceptance) | `test_phase5_heuristics.py` |
| Phase 6 -recognizers, gates, replay, Training API | `test_phase6_recognizers.py`, `test_phase6_adaptive_e2e.py` |
| Phase 7 -AI judge: verifier, budget, cache, redaction, authority | `test_phase7_ai_judge.py` |
| Phase 8 -remediation: recipes, inputs, verification, idempotence, API rescan | `test_remediation_e2e.py`, `test_download_fixed.py` |
| Phase 9 -framework views, recognizer persistence across a restart, secret-free stores | `test_phase9_frameworks_persistence.py` |
| Candidate remediation for unconfirmed vendors: eligibility, validation, simulation on a copy, verified / rejected / unverified, human confirmation, AI answer shape and prompt redaction, no vendor branch; asking the AI again after a rejection sends it the rejected command (redacted) and the reason | `test_candidate_remediation.py` |
| The three demo files (`demo-sih/`) go from a bad first scan to posture 100 with 0 findings: Cisco by one-click fixes, Palo Alto by seed write-back plus verified typed commands, the unknown vendor by teaching three lines and then verified commands | `test_demo_fix_to_100.py` |
| The verified corrected copy: retained only on verification and exactly equal to the simulated result, cleared by rejection and by a re-check that fails, downloadable only when verified or confirmed-after-verifying, one copy per candidate, correct content type and safe filename, never in SQLite, gone with the scan, `/download-fixed` still confirmed-vendor only, and the original `sample/juniper.cfg` byte-identical throughout | `test_candidate_remediation.py` |
| Derived remediation: a verified change from the configuration alone on Junos / PAN-OS / RouterOS / Huawei, the words come from the file's own block path, a setting that must exist is never deleted to silence a check, a block opener is never removed alone, a provisional finding cannot be derived from, confirmed vendors keep recipes, the upload and the scan never move | `test_derived_remediation.py` |
| Generic engine on hierarchical, terminator-separated dialects | `test_generic_hierarchical.py` |
| Resolution queue: the initial score is unchanged, the queue is exactly what coverage left out, a line can be picked and its meaning stated, an answer the line does not support is refused, teaching persists and the next scan reuses it, the resolved control becomes PASS or FAIL with recalculated posture and coverage, the uploaded configuration is unchanged, prose is reported unreadable and never scored | `test_resolution_queue.py` |
| Shipped seed knowledge: loading on a fresh database, idempotence, never overwriting what was taught, generalization across eleven dialects, no accidental or secret matches, unchanged Cisco / FortiGate and unknown-vendor behaviour, the fresh-deployment demo and teaching on top of it | `test_seed_knowledge.py`, fixtures in `tests/fixtures/seed_dialects/` |
| Brace-block Junos read by set-style seeds (same verdicts as its set twin, the leaf's own line cited), `inactive:` and `/* */` | `test_structured_braces.py` |
| RouterOS default SNMP community and plaintext user passwords; neither secret reaches a recognizer, the scan, the PDF or the ledger | `test_mikrotik_credentials.py` |
| Terraform: blocks flattened in place, AWS / Azure / GCP rules decided on the rule's own line, unresolved variables never decide, device-only checks N/A | `test_terraform.py`, fixtures in `tests/fixtures/terraform/` |
| Azure NSG and GCP firewall JSON exports: one rule per line, only an open Allow / INGRESS rule counts (deny, outbound, disabled do not), device-only checks N/A | `test_cloud_json.py`, fixtures in `tests/fixtures/cloud_json/` |
| Independent citation check over every benchmark and demo file (and the demo fleet): each cited line exists and says the cited text (a `<SECRET:…>` placeholder stands for its value), each attack-path step cites a decided FAIL of the same device on lines that result cites, posture and coverage recomputed from the returned results match | `test_citations.py` |
| CVE context by OS version: matched on the stated train only, nothing inferred, a broken cache means no data, scores / findings / paths / risk identical with and without it, shown in the PDF with the caveat | `test_cve.py` |
| Attack-path proof: per chain a positive configuration showing exactly that chain and a copy with only its fix showing none (expectations written first), the diff is only the fix, the recorded proof matches the catalog | `test_path_proof.py`, fixtures in `tests/fixtures/attack_paths/` |
| SONiC `config_db.json` tables and Cumulus NVUE: default communities fail, custom pass, syslog / NTP / TACACS+ read, a disabled NTP server never decided, community strings and TACACS keys never leave | `test_sonic_cumulus.py` |
| Recognizer generalization: one recognizer over many addresses, names and numbers; indentation, whitespace and statement order ignored; positive and negative forms opposite; the same leaf word in another block not matched; a value-sensitive setting giving different control results from one recognizer; half a multi-fact control left undecided; a taught concept reused on the next scan; a line that states nothing teaching only a setting it names, while a line that states an on/off may be named in any words; and the acceptance loop -five concepts taught through the API, a configuration of seven variant lines scanned, only the genuinely new control left in the queue | `test_recognizer_generalization.py` |
| Compliance report (PDF): a PDF per device and a zip for several, a hostname cannot escape the download name, no secret of the configuration reaches the document or the rendered bytes, serial numbers are not invented, provisional readings are never shown as PASS/FAIL, no vendor commands for an unconfirmed vendor, the deterministic change and its rescan checks for a confirmed one, unmapped frameworks named, undecided checks listed, a prose file reported unreadable | `test_pdf_report.py` |
| Parsers, pipeline, ACLs, FortiGate model and firmware from the `#config-version=` header | `test_pipeline.py`, `test_cisco_acl.py` |
| Adaptive layer and legacy interpreter, learned mappings, review API | `test_adaptive.py`, `test_adaptive_generic.py`, `test_adaptive_api_integration.py`, `test_phase3_adaptive_mapper.py`, `test_phase3_e2e.py`, `test_phase4_review_api.py`, `test_phase5_learned_mappings.py` |
| Settings, Groq key rotation | `test_config_loading.py`, `test_ai_client_key_rotation.py` |
| Optional API key: open when unset, `401` without or with a wrong `X-API-Key`, `/health` always open | `test_api_key.py` |
| `DATABASE_URL`: a raw password holding `@` or `$` is percent-encoded so the right host is used | `test_database_url.py` |
| Browser UI audit regressions -no secret in API responses, `config_index` identity, generic hostnames, manual-review consistency, CIS banner mapping, scan status | `test_ui_audit_regressions.py` |
| Accuracy benchmark floors (planted ≥ 18, fixtures ≥ 70, 0 missed, 0 false alarms) | `test_benchmark.py` |
| Prompt injection: the fence cannot be closed from inside, a fully hijacked AI changes no verdict | `test_prompt_injection.py` |
| Attack paths, evidence chain, contextual risk | `test_attack_paths.py`, `test_evidence_chain.py`, `test_risk.py` |
| Audit ledger: every scan and report recorded, a report PDF or a multi-device .zip verifies, any edit breaks the chain | `test_ledger.py` |
| Changes since the last audit (fixed, new, no longer decided) | `test_drift.py` |
| Checks across devices: shared SNMP community never shown, NTP / syslog mismatch | `test_fleet_checks.py` |
| Offline AI through a local OpenAI-compatible server | `test_local_ai.py` |
| Command line: exit codes, SARIF on the cited line, no secret in the output | `test_cli.py` |
| Organisation policy: tightens only, results cite it, CLI `--policy` | `test_policy.py` |
| Seed knowledge incl. LLDP on an external-zone interface and PAN-OS password length from its reviewed factory default | `test_seed_knowledge.py` |

Two live Groq tests in `test_adaptive_generic.py` are skipped unless `NETAUDIT_LIVE_AI=1` and a key are set.

## Frontend (`frontend/src/`)

| Area | Tests |
|---|---|
| Backend state to user-facing state, counts, next step, plain-language readings, safety-gate wording | `lib/domain.test.js` |
| Overview (`Results.jsx`): posture never overstated, honest counts, questions, the resolution queue of undecided checks, a file holding no configuration, the PDF report download | `app/Results.test.jsx` |
| Fix: the remediation classes, inputs, verified fix, download of verified changes only, candidate remediation for an unconfirmed vendor (derive, generate, review, verify, reject, confirm), *Ask AI for a command* offered again after a rejection, and the refusal when a removal cannot resolve a check | `app/Fix.test.jsx` |
| The verified corrected copy in the UI: no download without a candidate, none for a draft or a rejected one, the button and its "not applied to a device" warning once verified, the candidate endpoint (not `/download-fixed`) is what it calls, and the confirmed-vendor download is unchanged | `app/Fix.test.jsx` |
| Teach: the undecided check, choosing a suggested line or any line of the configuration, stating what it means, safety-gate failures in plain English, the saved recognizer and the updated posture / coverage / remaining count, a save that still decides nothing, skipping | `app/Teach.test.jsx` |
| Finding drawer: evidence, assurance, no invented commands, *Explain this* labelled as AI commentary and a failed call reported inline | `app/FindingDrawer.test.jsx` |
| Framework view | `app/Frameworks.test.jsx` |
| Expired history entries | `app/History.test.jsx` |
| Legacy review queue | `app/LegacyInterpretations.test.jsx` |
| Homepage claims, entering the application, expired scan | `App.test.jsx` |
| Shared hooks (reveal, sequence, reduced motion) | `lib/hooks.test.jsx` |
| Evidence and status primitives | `components/ui/ui.test.jsx` |
| Summary-only history | `utils/history.test.js` |
| Mapping form validation | `utils/adaptiveValidation.test.js` |
| Attack paths page, field-by-field compare, fleet view, drift, audit ledger, rules catalog | `app/AttackPaths.test.jsx`, `app/Baseline.test.jsx`, `app/Fleet.test.jsx`, `app/Drift.test.jsx`, `app/Ledger.test.jsx`, `app/Rules.test.jsx` |

## End to end (`frontend/e2e/`)

`demo.spec.js` runs the 2-minute judge path in a real browser against the real backend, on their own ports
(8011, 5183) with a throwaway database and AI off: scan Cisco + PAN-OS, Overview, compare fields, executive
summary, attack paths, verify the ledger and the downloaded report, a one-byte edit is caught, rules catalog.
Windows uses the installed Chrome (`PW_CHANNEL=msedge` to change); elsewhere run `npx playwright install chromium`
once.

## Run

```powershell
cd backend
venv\Scripts\python -m pytest tests -q -n auto   # 1644 passed, 2 skipped (~7 min in parallel)

cd ..\frontend
npm test                                    # 151 passed
npm run e2e                                 # 1 passed (starts its own servers)
npm run build
```

No linter or type checker is configured in the repository.
