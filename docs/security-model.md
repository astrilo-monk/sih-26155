# Security Model

What NetAuditAI trusts, what it never lets happen, and where each guarantee is enforced (and tested).

## Compliance authority

Only deterministic code decides a result:

* facts come from confirmed vendor parsers, documented defaults and administrator-confirmed recognizers
  (decisive), or from lexicon heuristics and verified AI proposals (provisional);
* controls (`app/controls/`) turn facts into PASS / FAIL / UNKNOWN / NOT_CONFIGURED;
* posture, coverage, findings counts, framework status and remediation read decisive results only.

PASS needs a cited line or a documented default. NOT_CONFIGURED is never PASS. For unknown vendors, absence is
never evidence: a missing setting is NOT_CONFIGURED, not FAIL.

## Guarantees

| Guarantee | Enforced in | Tested in |
|---|---|---|
| Secrets are redacted before any AI request (whole config redacted, excerpts and prompts scrubbed) | `app/ai/redaction.py`, `app/ai/judge.py` | `test_phase1_redaction.py`, `test_phase7_ai_judge.py` |
| AI output is provisional: never scored, counted, remediated or a framework PASS/FAIL | `controls/evaluate.py`, `analysis/scoring.py`, `controls/frameworks.py`, `remediation/engine.py` | `test_phase7_ai_judge.py`, `test_phase9_frameworks_persistence.py`, `test_remediation_e2e.py` |
| AI cannot infer PASS from absence; every citation is verified against the cited line and scope | `app/ai/judge.py` (verifier) | `test_phase7_ai_judge.py` |
| An AI fact answers only the control that asked | `SecurityFact.control_id`, `controls/evaluate.py` | `test_phase7_ai_judge.py` |
| Hallucinated or unverified citations never reach the review queue | `routes/adaptive.py`, `facts/recognizers.py` | `test_phase7_ai_judge.py` |
| API responses the browser renders carry no configuration secret: evidence, reasons, framework evidence, adaptive lines, review items, remediation diffs and fixed-config previews are redacted per configuration (the download is the only real file) | `routes/scan.py` (`config_redactor`, `redact_lines`, `display_scrub`), `routes/remediation.py`, `routes/adaptive.py` | `test_ui_audit_regressions.py`, `test_remediation_e2e.py` |
| A recognizer is never drafted or saved from a line that holds a secret | `routes/adaptive.py` (`_draft`) | `test_ui_audit_regressions.py` |
| A device is its `config_index`: a shared hostname never selects another upload's configuration | `routes/remediation.py`, `frontend/src/lib/domain.js`, `lib/useAudit.js` | `test_ui_audit_regressions.py`, `app/FindingDrawer.test.jsx` |
| A downloaded configuration matches the reviewed plan (a fix and a download may use only the inputs the shown plan was generated with) | `frontend/src/lib/useAudit.js` | `app/Fix.test.jsx` |
| The vendor is deterministic; look-alikes and mixed configs stay unverified | `parsers/detector.py`, `parsers/coverage.py` | `test_phase1_vendor_identification.py` |
| Recognizers require an administrator and pass safety gates; templates are typed slots, not regex | `facts/recognizers.py`, `db/mappings.py`, `adaptive/matcher.py` | `test_phase6_recognizers.py` |
| No secret is stored in the knowledge store (SQLite or Postgres) | `db/mappings.py` (`_refuse_secrets`, redacted rejections) | `test_phase9_frameworks_persistence.py` |
| Remediation only for decisive FAILs on confirmed vendors, never from caller or AI text, verified by rescan | `remediation/engine.py`, `routes/remediation.py` | `test_remediation_e2e.py` |
| A candidate command (typed or AI-proposed) is never executed, never edits the uploaded configuration, never enters the confirmed-vendor download and never changes results, posture or coverage; it is simulated on a copy and needs a human to confirm | `remediation/candidates.py`, `routes/remediation.py` | `test_candidate_remediation.py` |
| Only a candidate the simulation **verified** has a corrected copy to download; a draft, unverified, rejected or re-checked-and-failed candidate has none, and `/download-fixed` stays confirmed-vendor only | `routes/remediation.py`, `remediation/candidates.py` | `test_candidate_remediation.py` |
| A candidate exists only for a decisive FAIL on an unconfirmed vendor; a provisional verdict and a confirmed vendor are both refused | `routes/remediation.py` (`_candidate_target`) | `test_candidate_remediation.py` |
| An AI remediation proposal is refused unless it is exactly the expected shape for the control that asked, and its prompt carries no secret | `ai/remediation.py` | `test_candidate_remediation.py` |
| A derived candidate is built only from the configuration's own words, only for a control a removal can resolve (prohibitions and relational controls -never one that requires a setting or sets a threshold), never from a block opener, and it faces the same simulation and human confirmation as any other candidate | `remediation/candidates.py` (`derive`, `DERIVABLE_KINDS`, `block_openers`) | `test_derived_remediation.py` |
| The PDF report carries no configuration secret and states nothing the configuration does not -no serial number or chassis details (the FortiGate model and firmware only when its `#config-version=` header states them), no provisional reading presented as compliance, no vendor command for an unconfirmed vendor | `app/reporting/report.py` (built from the already-redacted scan response) | `test_pdf_report.py` |
| Teaching cannot assert a meaning the line does not state: an administrator's answer becomes an ordinary recognizer candidate and faces every gate, including the secret refusal | `facts/teaching.py`, `facts/recognizers.py` (`draft_recognizer`, `validate_recognizer`) | `test_resolution_queue.py` |
| Operator inputs are validated before they are written into a template | `remediation/recipes.py` (`parse_inputs`) | `test_remediation_e2e.py` |
| An AI explanation of a finding is labelled AI-written commentary, not evidence, and never changes a status, severity or count | `frontend/src/app/FindingDrawer.jsx`, `routes/assistant.py` | `app/FindingDrawer.test.jsx` |
| The browser history stores no evidence or configuration lines | `frontend/src/utils/history.js` | `history.test.js` |

## Not protected (prototype)

* Access control is one optional shared key: with `API_KEY` set, every `/api` route (not `/health`) requires a
  matching `X-API-Key` header, compared in constant time (`app/main.py`, `test_api_key.py`). There are no users or
  roles, and by default the key is empty, so anyone who reaches the API can confirm recognizers or download
  remediated configurations. CORS allows every origin unless `CORS_ORIGINS` narrows it.
* Redaction is pattern-based; a secret behind a keyword it does not know could reach the AI.
* `POST /api/download-fixed` returns the real configuration, including its own secrets and the NTP key the
  operator typed. Response redaction uses the same pattern-based redactor, so an unknown secret syntax is not
  redacted there either. Values equal to a secret are redacted wherever they stand as a whole token, so a username
  equal to its password is shown as `<SECRET:redacted>`.
* A generated fix is verified against NetAuditAI's own parser and controls, not on a device. Review it before
  deploying (warnings flag lockout and VPN-peer risks).
* A **verified candidate** is a weaker statement still: it says the proposed text removes the finding from the
  uploaded configuration *file*, as the generic engine reads it. It says nothing about the real CLI syntax, about
  side effects on the device, or about whether the command is safe to run. NetAuditAI never connects to a device.
* The **verified corrected copy** (`POST /api/remediation/candidate/download`) is the administrator's own uploaded
  file with that one simulated change -it adds nothing and redacts nothing, exactly like `/download-fixed`, and it
  is labelled as a copy that has not been applied to a device. Only a verified candidate can produce one; the
  status gate is checked on the server, not in the browser. One copy per candidate: changes are never combined.
* A command an administrator types is scrubbed with the configuration's known secrets before it is shown again, but
  a **new** secret typed into a command (a key the configuration does not contain) is not detectable and is held in
  memory for the life of the scan. Candidates are never written to the database.
