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

### `POST /api/remediate`
Generate deterministic remediation commands for one finding.
* **Request JSON:**
  ```json
  {
    "scan_id": "123-abc",
    "rule_id": "MGMT-001",
    "device_hostname": "CORP-RTR-01"
  }
  ```
* **Response JSON:**
  ```json
  {
    "rule_id": "MGMT-001",
    "title": "Insecure Management Protocol (Telnet) Enabled",
    "device_hostname": "CORP-RTR-01",
    "vendor": "cisco_ios",
    "original_lines": ["transport input telnet ssh"],
    "remediation_commands": "line vty 0 4\n transport input ssh\n no transport input telnet",
    "explanation": "This restricts VTY access to SSH only, removing Telnet."
  }
  ```

### `POST /api/verify`
Apply remediation commands to a copy of the config and re-analyze it.
* **Request JSON:** `{"scan_id": "123-abc", "remediation_commands": "line vty 0 4\n transport input ssh"}`
* **Response JSON:** `VerifyResponse` with original vs. new scores and remaining findings.
* **Known issue:** for Cisco configs the preview does not yet reflect only the supplied commands.

### `POST /api/download-fixed`
Download the fully remediated configuration(s) for a scan.
* **Request JSON:** `{"scan_id": "123-abc"}`

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
