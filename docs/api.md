# API Documentation

The FastAPI backend exposes the endpoints below. All routes except `/health` are under `/api`. Interactive docs are available at `http://localhost:8000/docs` when the backend is running.

Request and response models are defined in `backend/app/api/schemas.py`.

## Health

### `GET /health`
Returns a simple status payload confirming the backend is running.

## Scanning

### `POST /api/scan`
Upload one or more raw configuration files for analysis.
* **Request:** `multipart/form-data` with one or more `files` fields (UTF-8 text, max 2 MB each).
* **Response:** `ScanResultResponse`:
  * `scan_id`, `timestamp`, `devices[]` in upload order (hostname, vendor — `unknown` unless confirmed). For a
    configuration no parser reads, the hostname is the one a single statement states (`hostname X`, `system-name X`,
    `set … hostname X`); `unknown` when absent or conflicting. Hostnames can repeat: a device is identified by its
    position, `config_index`.
  * `vendor_identification[]`: `detected_vendor`, `status` (`confirmed` / `unverified` / `unknown`), `parse_coverage`, `uncovered_lines`, `reason`
  * `results[]`: every control for every config — `status`, `assurance`, `proposed_status` (AI verdict awaiting confirmation), `scope`, `reason`, `evidence`
  * `findings[]`: FAIL results with their `config_index` (`assurance` heuristic = suspected, not scored) and severity counts
  * Every configuration quote (evidence lines, reasons, adaptive lines and their context) is redacted with that
    configuration's own secrets, e.g. `username admin password 0 <SECRET:type0>`. Evidence keeps its line numbers.
  * `posture` (null when nothing decided), `coverage`, `posture_bounds`, `critical_unassessed`
  * `frameworks[]`: the same results by framework version — `coverage`, `counts`, `requirements[]` (`status` pass / fail / partial / unknown / not_configured / n_a, `provisional`, mapped `controls[]` with status, assurance, evidence)
  * `score`: **deprecated** penalty score, kept for existing scripts; do not use for compliance
* **`adaptive` block:** present when lines went through the adaptive layer. It holds:
  * `ai_calls`, `ai_cache_hits`: AI judge requests and cached answers for this config
  * `unrecognized_lines`, each with its `structural_path`
  * `ai_mappings`: source, confidence tier, status, cited `value_evidence`
  * `learned_matches`
  * `ai_called`
  * `ai_unavailable_lines`
  * `vendor_evidence`: likely vendor plus `identified` / `conflicting` / `unknown`, for information only
  * the reasons a score is provisional

### `GET /api/scan/{scan_id}`
Retrieve a previous scan from the in-memory store (`404` after a backend restart).

### `GET /api/scan/{scan_id}/status`
Whether the backend still holds a scan: `{"scan_id": "123-abc", "held": false}` (always `200`). The History page uses it
to mark entries expired after a restart.

## Remediation

Remediation is deterministic (`backend/app/remediation/`). It runs only for a **decisive FAIL** (parser, confirmed recognizer or documented default) on a **confirmed Cisco IOS / FortiGate** configuration. It is reported `fixed` only after the generated configuration was rescanned and verified. No request field carries command text, and AI output is never used.

For a configuration whose vendor is **not** confirmed, `/api/remediation/candidate*` offers reviewed *candidate*
remediation instead: command text an administrator typed or the AI proposed, validated, simulated on a copy of the
uploaded configuration where an effect can be derived, and confirmed by a human. A candidate is never executed,
never applied and never downloaded.

Every remediation response (`RemediationResponse`) has:

| Field | Meaning |
|---|---|
| `status` | `fixed` · `needs_input` · `manual_review` · `verification_failed` · `no_recipe` · `vendor_unverified` · `provisional` · `not_failing` |
| `reason`, `explanation`, `warnings` | Why this status; what the recipe changes (empty for `manual_review`: nothing was generated); operational warnings |
| `scopes`, `evidence` | Failing scopes and the cited configuration lines (before state) |
| `required_inputs`, `missing_inputs` | Operator values the recipe uses / still needs |
| `diff` | The proposed deterministic change (unified diff) |
| `fixed_config` | Generated configuration (after state), for review; also returned when verification failed |

`evidence`, `diff` and `fixed_config` are **redacted** (the configuration's secrets and the `ntp_key` input become
`<SECRET:…>`). Only `POST /api/download-fixed` returns the real, deployable configuration.
| `checks` | Rescan checks: `vendor`, `parse_coverage`, `target`, `no_regression` |
| `control_status_before` / `_after`, `before` / `after` | Control status and posture, coverage, critical-unassessed, parse coverage before and after |

Inputs (all optional, validated, `422` when invalid): `syslog_server` and `ntp_server` (IPv4), `ntp_key_id` (1–65535), `ntp_key` (8–32 characters of `A-Z a-z 0-9 . _ + = @ % -`), `management_subnet` (IPv4 CIDR, not `/0`).

### `POST /api/remediate`
Remediate one control on one device.
* **Request JSON:** `{"scan_id": "123-abc", "rule_id": "LOG-001", "device_hostname": "CORP-RTR-01", "config_index": 0, "inputs": {"syslog_server": "10.20.0.5"}}`
* `config_index` selects the uploaded configuration (the UI always sends the finding's `config_index`); the hostname
  must match it. Without `config_index`, a hostname shared by several uploads is refused with `409`.
* **Response JSON:** `RemediationResponse`, e.g. `{"status": "fixed", "diff": "…\n+logging host 10.20.0.5\n end", "checks": [{"name": "target", "passed": true, "detail": "LOG-001 now passes: Logs are forwarded to 10.20.0.5"}, …], …}`. Without the input: `{"status": "needs_input", "missing_inputs": ["syslog_server"], "fixed_config": null, …}`. Unknown or unverified vendor: `{"status": "vendor_unverified", …}`.

### `POST /api/remediation/plan`
Remediate every failing control of every device, in catalog order, verifying each step.
* **Request JSON:** `{"scan_id": "123-abc", "inputs": {}}`
* **Response JSON:** `RemediationPlanResponse`: `inputs` (every input spec) and `devices[]`, each with `vendor_status`, `remediations[]`, `candidates[]` (unconfirmed vendors), `fixed_controls`, the combined `checks`, `before` / `after` and `fixed_config` (every verified change; `null` when none).

### `POST /api/remediation/candidate*` (unconfirmed vendors)

Five operations on one candidate. A candidate is identified by the finding it is about, so at most one candidate per
(`config_index`, `rule_id`) exists at a time and a new proposal replaces it. Candidates live in the scan's memory
only — they are never written to the database.

All five take the same body: `{"scan_id": "123-abc", "rule_id": "MGMT-001", "device_hostname": "JUNIPER-EDGE-01", "config_index": 0, "command": "delete system services telnet;", "reason": null}` (`command` is required for
`/candidate` and ignored elsewhere; `reason` is used by `/reject`).

| Route | Does |
|---|---|
| `POST /api/remediation/candidate` | Record the command an administrator typed → `draft` (`422` when the text is empty, over 2000 characters, over 20 lines, or holds control characters) |
| `POST /api/remediation/candidate/generate` | Ask the AI for one → `draft`, `source: "ai"` (`503` when AI is unavailable or its answer is not exactly the expected shape) |
| `POST /api/remediation/candidate/verify` | Simulate it on a copy and re-evaluate every control → `verified` / `rejected` / `unverified` |
| `POST /api/remediation/candidate/confirm` | An administrator accepts a `verified` or `unverified` candidate → `confirmed` (`409` from any other state: a draft must be checked first) |
| `POST /api/remediation/candidate/reject` | Discard it → `rejected`; nothing about the scan changes |

Common refusals: `404` unknown control, unknown device, or no candidate yet; `409` the vendor **is** confirmed (use
`POST /api/remediate`); `409` the finding is not decided from validated evidence (a heuristic or AI verdict — confirm
the reading on the Teach page first).

Every response is a `RemediationCandidateSchema`:

| Field | Meaning |
|---|---|
| `source` | `manual` · `ai` |
| `status` | `draft` · `verified` · `unverified` · `rejected` · `confirmed` |
| `command` | The proposed text, redacted for display. It is never executed |
| `reason` | What the state means, in full sentences |
| `explanation`, `confidence`, `assumptions` | From an AI proposal (`low` / `medium` / `high`); empty for a typed command |
| `evidence` | The failing lines the candidate has to address (redacted) |
| `control_status_before` / `_after` | The control before and on the simulated copy, e.g. `fail` → `not_configured` (absence is never a PASS) |
| `checks` | `target`, `no_regression`, `generic_path` — empty when nothing could be simulated |
| `diff` | The simulated change on the copy (redacted). The uploaded configuration is untouched |
| `created_at`, `confirmed_at` | When it was proposed and, if it happened, confirmed |

A device's candidates are also returned with the plan (`devices[].candidates`), so a reload shows the same state.
**A confirmed candidate is not a fix:** the control still FAILs until the device is changed and scanned again.

### `POST /api/download-fixed`
Download the configuration(s) with every verified fix applied (unverified changes are never included).
* **Request JSON:** `{"scan_id": "123-abc", "inputs": {}}`
* **Response:** one `.cfg` (text/plain) or a `.zip` of `<hostname>_fixed.cfg`. `409` when no configuration has a confirmed vendor; `400` when nothing was verified.
* The UI sends exactly the inputs the displayed plan was generated with, and disables the download while the input
  fields differ from them, so a downloaded file always matches a reviewed plan.

## Assistant (AI)

### `GET /api/assistant/status`
Report whether AI features are configured: `{"ai_available": true}`. **Known issue:** this returns `true` whenever a key is set, even if the Groq quota is exhausted.

### `GET /api/assistant/explain/{scan_id}/{rule_id}/{hostname}`
Explain a specific finding. Falls back to static text without AI.

### `GET /api/assistant/summary/{scan_id}`
Summarize the scan results. Falls back to static text without AI.

### `POST /api/assistant/chat`
Ask a question about a scan.
* **Request JSON:** `{"scan_id": "123", "message": "What does rule MGMT-001 mean?"}`
* **Response JSON:** `{"response": "...", "scan_id": "123"}`

## Adaptive Training

These endpoints back the Teach and Learned pages. **They have no authentication yet.** A mapping or recognizer whose text holds a secret (password, key, community string) is refused with `422`; rejected lines are stored redacted.

### `GET /api/adaptive/scans/{scan_id}/provisional`
Undecided or provisional control results of unknown-vendor configs, with the heuristic lines and verified AI proposal lines an administrator can confirm.

### `POST /api/adaptive/scans/{scan_id}/recognizers/draft`
Draft a recognizer from a provisional line. **Request JSON:** `{"config_index": 0, "control_id": "MGMT-001", "line_number": 71, "command_pattern": null, "scope_template": null, "value": null, "any_dialect": false, "negatives": []}`. **Response:** the draft, gate `errors` and the `replay` of results it would change on scans held by the backend.

### `POST /api/adaptive/scans/{scan_id}/recognizers`
Save the recognizer (same body) to SQLite and return the re-evaluated scan. `422` when a gate fails, `409` on a conflicting recognizer.

### `POST /api/adaptive/scans/{scan_id}/provisional/reject`
Record a provisional line as reviewed-but-unmapped: heuristics and AI ignore it on later scans. **Request JSON:** `{"config_index": 0, "control_id": "MGMT-001", "line_number": 71, "reason": null}`.

The review-queue endpoints below serve the legacy line interpreter (`ADAPTIVE_AI_FOR_KNOWN_VENDORS`, off by default).

### `GET /api/adaptive/fields`
Normalized fields an interpretation may map to. Each entry has `field`, `value_type`, `label`, `description` and `value_rule`. The list comes from `backend/app/models/field_catalog.py`.

### `GET /api/adaptive/scans/{scan_id}/review?include_resolved=false`
Review queue for a scan: MEDIUM/LOW/contradicted and AI-unavailable interpretations. Each item includes its `structural_path`.

### `POST /api/adaptive/scans/{scan_id}/review/{item_id}/accept`
Accept the AI's interpretation and save it as a learned mapping.
* **Request JSON (optional fields):** `{"concept": "...", "command_pattern": "..."}`

### `POST /api/adaptive/scans/{scan_id}/review/{item_id}/edit`
Save a corrected mapping.
* **Request JSON:** `{"normalized_field": "services.ssh_enabled", "extracted_value": "true", "concept": null, "command_pattern": null}`

### `POST /api/adaptive/scans/{scan_id}/review/{item_id}/reject`
Reject an interpretation. The line is not sent to the AI again.
* **Request JSON (optional):** `{"reason": "..."}`

Accept, edit and reject all return `ReviewActionResponse`:
* the updated `item`
* the saved `mapping` (if any)
* `auto_resolved`: other pending lines resolved by the new mapping
* the re-analyzed `scan`

### `GET /api/adaptive/mappings?include_inactive=false`
List learned mappings.

### `PATCH /api/adaptive/mappings/{mapping_id}`
Edit a learned mapping. Any of these may be supplied:
`concept`, `normalized_field`, `vendor`, `command_pattern`, `extraction_method`, `constant_value`, `active`.
Returns `404` if the mapping is not found, `409` on a conflict with another mapping, and `422` if the mapping is invalid.

### `DELETE /api/adaptive/mappings/{mapping_id}`
Deactivate a learned mapping. It is kept for audit but no longer matched.
