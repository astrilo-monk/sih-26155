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
| A device is its `config_index`: a shared hostname never selects another upload's configuration | `routes/remediation.py`, `FindingDetail.jsx` | `test_ui_audit_regressions.py`, `FindingDetail.test.jsx` |
| A downloaded configuration matches the reviewed plan | `RemediationQueue.jsx` | `RemediationQueue.test.jsx` |
| The vendor is deterministic; look-alikes and mixed configs stay unverified | `parsers/detector.py`, `parsers/coverage.py` | `test_phase1_vendor_identification.py` |
| Recognizers require an administrator and pass safety gates; templates are typed slots, not regex | `facts/recognizers.py`, `db/mappings.py`, `adaptive/matcher.py` | `test_phase6_recognizers.py` |
| No secret is stored in the SQLite knowledge store | `db/mappings.py` (`_refuse_secrets`, redacted rejections) | `test_phase9_frameworks_persistence.py` |
| Remediation only for decisive FAILs on confirmed vendors, never from caller or AI text, verified by rescan | `remediation/engine.py`, `routes/remediation.py` | `test_remediation_e2e.py` |
| Operator inputs are validated before they are written into a template | `remediation/recipes.py` (`parse_inputs`) | `test_remediation_e2e.py` |
| The browser history stores no evidence or configuration lines | `frontend/src/utils/history.js` | `history.test.js` |

## Not protected (prototype)

* No authentication or authorization on any endpoint; anyone who reaches the API can confirm recognizers or
  download remediated configurations. CORS allows every origin.
* Redaction is pattern-based; a secret behind a keyword it does not know could reach the AI.
* `POST /api/download-fixed` returns the real configuration, including its own secrets and the NTP key the
  operator typed. Response redaction uses the same pattern-based redactor, so an unknown secret syntax is not
  redacted there either. Values equal to a secret are redacted wherever they stand as a whole token, so a username
  equal to its password is shown as `<SECRET:redacted>`.
* A generated fix is verified against NetAuditAI's own parser and controls, not on a device. Review it before
  deploying (warnings flag lockout and VPN-peer risks).
