# API Documentation

Our FastAPI backend will expose these endpoints for the frontend to consume.

*(Status: All endpoints are planned, basic router scaffolding exists in main.py)*

### `POST /api/v1/scan`
Upload a raw configuration file for analysis.
* **Request:** `multipart/form-data` containing the file.
* **Response:** Returns a `ScanResult` object containing the `scan_id`, vendor detected, overall score, and a list of `Finding` objects.

### `GET /api/v1/scan/{scan_id}`
Retrieve the results of a previous scan from the SQLite database.
* **Response:** Returns the `ScanResult` object.

### `POST /api/v1/ai/remediate`
Ask Gemini to generate remediation commands for a specific finding.
* **Request JSON:**
  ```json
  {
    "scan_id": "123-abc",
    "rule_id": "SEC-003"
  }
  ```
* **Response JSON:**
  ```json
  {
    "remediation_text": "To disable telnet and enable SSH on Cisco IOS...",
    "commands": ["line vty 0 4", "transport input ssh"]
  }
  ```

### `POST /api/v1/ai/chat` (Stretch Goal)
Send a message to the AI assistant regarding a specific scan.
* **Request JSON:** `{"scan_id": "123", "message": "What does rule SEC-003 mean?"}`
* **Response:** Streaming text response from Gemini.
