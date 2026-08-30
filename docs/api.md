# API Documentation

Our FastAPI backend exposes the following endpoints for the frontend to consume.

*(Status: All endpoints are fully implemented.)*

### `POST /api/scan`
Upload one or more raw configuration files for analysis.
* **Request:** `multipart/form-data` containing the file(s).
* **Response:** Returns a `ScanResultResponse` object containing the `scan_id`, overall score, device details, and a list of `Finding` objects.

### `GET /api/scan/{scan_id}`
Retrieve the results of a previous scan from the in-memory store.
* **Response:** Returns the `ScanResultResponse` object.

### `POST /api/remediate`
Generate deterministic remediation commands for a specific finding.
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
Apply the remediation commands to a copy of the config and re-analyze to verify the fix works.
* **Request JSON:**
  ```json
  {
    "scan_id": "123-abc",
    "remediation_commands": "line vty 0 4\n transport input ssh"
  }
  ```
* **Response JSON:** Returns a `VerifyResponse` with original vs. new scores and remaining findings.

### `GET /api/assistant/explain/{scan_id}/{rule_id}/{hostname}`
Ask Gemini to generate an in-depth explanation for a specific finding.

### `GET /api/assistant/summary/{scan_id}`
Ask Gemini to generate an executive summary of the overall scan results.

### `POST /api/assistant/chat`
Send a message to the AI assistant regarding a specific scan.
* **Request JSON:** `{"scan_id": "123", "message": "What does rule MGMT-001 mean?"}`
* **Response JSON:** `{"response": "...", "scan_id": "123"}`
