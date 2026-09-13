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
* **Response:** `ScanResultResponse`, containing the `scan_id`, score, device details and findings.
* **`adaptive` block:** present when lines went through the adaptive layer. It holds:
  * `unrecognized_lines`, each with its `structural_path`
  * `ai_mappings`: source, confidence tier, status, cited `value_evidence`
  * `learned_matches`
  * `ai_called`
  * `ai_unavailable_lines`
  * `vendor_evidence`: likely vendor plus `identified` / `conflicting` / `unknown`, for information only
  * the reasons a score is provisional

### `GET /api/scan/{scan_id}`
Retrieve a previous scan from the in-memory store.

## Remediation

Remediation is deterministic (`backend/app/remediation/`). It runs only for a **decisive FAIL** (parser, confirmed recognizer or documented default) on a **confirmed Cisco IOS / FortiGate** configuration. It is reported `fixed` only after the generated configuration was rescanned and verified. No request field carries command text, and AI output is never used.

Every remediation response (`RemediationResponse`) has:

| Field | Meaning |
|---|---|
| `status` | `fixed` · `needs_input` · `manual_review` · `verification_failed` · `no_recipe` · `vendor_unverified` · `provisional` · `not_failing` |
| `reason`, `explanation`, `warnings` | Why this status; what the recipe changes; operational warnings |
| `scopes`, `evidence` | Failing scopes and the cited configuration lines (before state) |
| `required_inputs`, `missing_inputs` | Operator values the recipe uses / still needs |
| `diff` | The proposed deterministic change (unified diff) |
| `fixed_config` | Generated configuration (after state); also returned when verification failed, for review |
| `checks` | Rescan checks: `vendor`, `parse_coverage`, `target`, `no_regression` |
| `control_status_before` / `_after`, `before` / `after` | Control status and posture, coverage, critical-unassessed, parse coverage before and after |

Inputs (all optional, validated, `422` when invalid): `syslog_server` and `ntp_server` (IPv4), `ntp_key_id` (1–65535), `ntp_key` (8–32 characters of `A-Z a-z 0-9 . _ + = @ % -`), `management_subnet` (IPv4 CIDR, not `/0`).

### `POST /api/remediate`
Remediate one control on one device.
* **Request JSON:** `{"scan_id": "123-abc", "rule_id": "LOG-001", "device_hostname": "CORP-RTR-01", "config_index": null, "inputs": {"syslog_server": "10.20.0.5"}}`
* **Response JSON:** `RemediationResponse`, e.g. `{"status": "fixed", "diff": "…\n+logging host 10.20.0.5\n end", "checks": [{"name": "target", "passed": true, "detail": "LOG-001 now passes: Logs are forwarded to 10.20.0.5"}, …], …}`. Without the input: `{"status": "needs_input", "missing_inputs": ["syslog_server"], "fixed_config": null, …}`. Unknown or unverified vendor: `{"status": "vendor_unverified", …}`.

### `POST /api/remediation/plan`
Remediate every failing control of every device, in catalog order, verifying each step.
* **Request JSON:** `{"scan_id": "123-abc", "inputs": {}}`
* **Response JSON:** `RemediationPlanResponse`: `inputs` (every input spec) and `devices[]`, each with `vendor_status`, `remediations[]`, `fixed_controls`, the combined `checks`, `before` / `after` and `fixed_config` (every verified change; `null` when none).

### `POST /api/download-fixed`
Download the configuration(s) with every verified fix applied (unverified changes are never included).
* **Request JSON:** `{"scan_id": "123-abc", "inputs": {}}`
* **Response:** one `.cfg` (text/plain) or a `.zip` of `<hostname>_fixed.cfg`. `409` when no configuration has a confirmed vendor; `400` when nothing was verified.

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

These endpoints back the Training tab. **They have no authentication yet.**

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
