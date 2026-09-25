# Bugs found in the codebase audit

Audit date: 2026-09-25, branch `feat/severity-colors`. **Nothing has been fixed.** This file only lists what was found.

Baseline: all tests pass (backend 1227 passed and 2 skipped; frontend 119 passed). None of the bugs below is covered by a test.

Each entry has a **Verified** line:
- **reproduced**: a small script showed the wrong behaviour.
- **by reading**: found by reading the code, not run.

---

## High: wrong verdicts or leaked secrets

### 1. Multi-VDOM FortiGate configs: nothing is parsed, but the vendor is "confirmed" and the defaults PASS
- **Where:** `backend/app/parsers/fortinet.py`. The code matches each block by its exact first line (`ctx[0] == "config system interface"`, `("config system global",)` and so on). This happens at lines 124, 148, 194, 231, 253, 276, 299, 347 and 384.
- **What:** A FortiGate with VDOMs enabled wraps every block in `config global` or `config vdom` / `edit root`. After that wrapping, none of the exact matches hit. Vendor detection still reports **confirmed**, because every line follows FortiOS grammar. The evaluator then falls back to FortiOS defaults.
- **Verified:** reproduced. The config below has telnet/http in `allowaccess` on `wan1`, SNMP community `public`, and `admintimeout 480`. The parser output was: hostname `unknown`, telnet `False`, communities `[]`, policies `0`. It then reported **PASS** for:
  - MGMT-004 ("No SNMP community is configured")
  - MGMT-006 ("Idle sessions time out after 5 minutes or less"), on a device set to 480
  - MGMT-007
  - BOUNDARY-002

  The config:
  ```
  config global
  config system global
      set admintimeout 480
  end
  config system interface
      edit "wan1"
          set allowaccess ping https ssh telnet http
  ...
  ```
- **Impact:** Critical problems are reported as compliant on a common real-world export format.

### 2. Cisco `snmp-server community <name>` with no RO/RW is ignored, and MGMT-004 PASSes
- **Where:** `backend/app/parsers/cisco_ios.py:184`. The regex is `^snmp-server community\s+(\S+)\s+(RO|RW)`. It requires `RO` or `RW`, and it is case-sensitive.
- **What:** These forms are not parsed:
  - `snmp-server community public`, where RO is the IOS default
  - `snmp-server community public ro` (lowercase)
  - `snmp-server community public view V RO`
- **Verified:** reproduced. Adding `snmp-server community public` to `cisco_secure.cfg` gives `MGMT-004 pass (default): "No SNMP community is configured"`.
- **Impact:** The default `public` community is reported as compliant. Because `ios_snmp` never sees the line, it also isn't redacted from parsed communities.

### 3. FortiGate `set proposal` and `set dhgrp`: only the first value is read
- **Where:** `backend/app/parsers/fortinet.py:357-364`. `prop.encryption = vals[0]`, `prop.hash_algorithm = vals[0]`, and `prop.dh_group = int(vals[0])`.
- **What:** `set proposal aes256-sha256 3des-md5` and `set dhgrp 14 1` are read as `('aes256-sha256', 14)`. The weak `3des-md5` and DH group 1 are never judged. Note that the remediation recipe (`forti_crypto`) does read every token, so the parser and the recipe disagree.
- **Verified:** reproduced.
- **Impact:** CRYPTO-001 can pass a tunnel that still negotiates 3DES/MD5 or DH group 1.

### 4. Mixed upload with AI unavailable: confirmed-vendor devices lose all findings and score
- **Where:** `backend/app/api/routes/scan.py:593`. The code is `if not (had_unknown_vendor and not had_ai_available and not anything_applied)`.
- **What:** One unreadable file in a multi-file upload, with no Groq key configured, turns the **whole** scan into display-only (`result = None`). That includes a Cisco/FortiGate device that was fully parsed.
- **Verified:** reproduced with `is_available` patched to return `False`.
  - `cisco_vulnerable.cfg` alone: 19 findings, score 0.
  - The same file uploaded together with a text file of notes: findings `None`, score `None`.
- **Impact:** Findings silently disappear for a device the engine could assess. The assistant summary and the explain endpoint also return 409 for that scan.

### 5. Secret redaction misses several real keyword forms
- **Where:** `backend/app/ai/redaction.py:43-72` (`_EXACT_KEYWORDS` and `_COMPOUND_KEYWORDS`).
- **What:** These lines pass through unredacted (reproduced):
  - `set enckey 0123456789abcdef`: FortiOS IPsec manual key
  - `set authkey 0123abcd`: FortiOS IPsec manual key
  - `set ddns-key c2VjcmV0`: FortiOS DDNS
  - `set apikey …`, `set bindpw …`, `set sharedkey …`, `set key-inbound …`
- **Impact:** Because the `Redactor` never learns these values, they are sent to the AI provider in judge/chat prompts. They also appear in API responses, the PDF report and the scan archive in the database, all of which are documented as secret-free.

---

## Medium

### 6. `/download-fixed` builds filenames and zip entry names from the raw hostname
- **Where:** `backend/app/api/routes/remediation.py:457`, `464` and `472`.
- **What:** The candidate download sanitizes its filename with `_safe_name()`. This endpoint does not. It writes `filename="{hostname}_fixed.cfg"` and the zip entry `f"{hostname}_fixed.cfg"` directly. The hostname comes from the uploaded file: Cisco `hostname (\S+)`, or FortiOS `set hostname "…"`, which can hold `"`, `/`, `..` or `%`. The effects:
  - A `"` breaks the `Content-Disposition` header.
  - `../x` gives path-traversal zip entry names.
  - `%` makes `decodeURIComponent` throw in `frontend/src/api/client.js:49`, so the download fails in the browser.
- **Verified:** by reading.

### 7. Blocking work runs inside `async def` endpoints and freezes the server
- **Where:** Every route is `async def`, but it calls synchronous, slow code:
  - SSH collection: `routes/collect.py:93-95`. The timeout can be up to 300 s, and devices are collected one after another.
  - Groq HTTP calls: `routes/assistant.py:121`, `routes/scan.py:569` (AI judge), and `routes/remediation.py:345`.
  - Postgres I/O: `load_scan`, `save_scan` and the repositories.
- **What:** Each of these blocks the single event loop. While one device is being collected, or one AI call is waiting, every other request to the backend hangs, including `/health`.
- **Verified:** by reading. FastAPI only runs plain `def` routes in a threadpool.

### 8. A malformed host crashes the whole live-collection request
- **Where:** `backend/app/collect/collector.py:166`. Only `socket.gaierror` is caught.
- **What:** `socket.getaddrinfo("a..b", None)` raises `UnicodeError`, which isn't a `CollectionError`. It escapes `collect()`, and `/api/collect` returns 500 for every target. The intended behaviour is to report per-host failure and still scan the devices that answered.
- **Verified:** reproduced (`_vetted_address('a..b', 'private')` raises `UnicodeError`).

### 9. `generate()` doesn't move to the next Groq key on 401/403/404
- **Where:** `backend/app/ai/client.py:115-121`.
- **What:** `request_structured()` skips a key-specific failure and tries the next key. `generate()` only does that for 429; it returns `None` on anything else. `.env.example` and the README both say the next key is used on 401/403/404.
- **Impact:** Chat, explain and summary stop working when `GROQ_API_KEY` is revoked, even though `GROQ_API_KEY_1` is valid.
- **Also:** `_is_rate_limited` matches `"429"` anywhere in the message, so an unrelated error that contains that substring is treated as a rate limit.
- **Verified:** by reading.

### 10. Cisco `no service timestamps log …` is read as timestamps enabled
- **Where:** `backend/app/parsers/cisco_ios.py:222-230`. The checks are substring tests: `"service timestamps log …" in line`.
- **Verified:** reproduced. With only `no service timestamps log datetime msec` present, `timestamps_enabled` is `True`.

### 11. Cisco extended ACL: a source port is parsed as the destination
- **Where:** `backend/app/parsers/cisco_ios.py:503-535` (`_parse_extended_acl_rest`).
- **What:** Port qualifiers after the source (`eq`, `range`, `gt`, `lt`, `neq`) aren't consumed.
  - `permit udp any eq bootps any` gives destination `eq bootps`.
  - `permit tcp 10.0.0.0 0.0.0.255 eq 22 host 1.1.1.1` gives destination `eq 22`.
- **Verified:** reproduced.
- **Impact:** Any-to-any detection (BOUNDARY-001) and any other check that reads `destination` can be wrong. For example, `permit tcp any eq 80 any` is not seen as any → any.

### 12. PDF report: the "Configuration change" command list is wrong
- **Where:** `backend/app/reporting/report.py:204-214` (`_diff_commands`).
- **What:**
  - A removed line that already starts with `no ` is printed unchanged. Removing `no service password-encryption` lists the command `no service password-encryption`, which is the opposite of the change.
  - FortiOS diffs get the Cisco `no` prefix, so the report prints lines like `no set allowaccess …`. That is not valid FortiOS.
  - Unified-diff context lines are dropped, so a change inside `line vty 0 4`, `interface X` or `config system global` is printed without its parent block.
- **Verified:** by reading.

### 13. The in-memory scan store is never pruned, and recognizer replay walks all of it
- **Where:** `backend/app/api/routes/scan.py:67` (`_scan_store`) and `backend/app/api/routes/adaptive.py:427` (`_replay`).
- **What:** Every scan keeps its full configuration, parsed model and results in process memory until restart, so memory grows without limit.
- **Also:** Each recognizer draft or save runs `evaluate_controls` twice for **every** unknown-vendor config held by the process, and returns the hostnames of other users' scans in `replay`.
- **Verified:** by reading.

### 14. Negative `config_index` picks the last config instead of returning 404
- **Where:** `backend/app/api/routes/adaptive.py:396` (`_unknown_config`), `:658` (`list_config_lines`) and `:528` (draft response).
- **What:** No schema or route checks `config_index >= 0`, so `entry["configs"][-1]` silently returns the last config. For comparison, `remediation._index` and `report.py` do check the range.
- **Verified:** by reading.

### 15. Frontend: a stale plan or queue response can overwrite the new scan's state
- **Where:** `frontend/src/lib/useAudit.js:43-87`.
- **What:** `fetchPlan` and `loadQueue` don't cancel, and don't check that the scan they were started for is still current. If the user opens scan B while scan A's plan is still loading, A's plan (and its candidates and `inputs.current`) lands after the reset for B. The Fix page then shows the wrong scan's fixes. The effect that opens a scan in `AppShell` guards against this with an `active` flag; these hooks don't.
- **Verified:** by reading.

### 16. PDF report: "Checks needing input" counts N/A controls
- **Where:** `backend/app/reporting/report.py:134`.
- **What:** The count is every control that is neither passed nor failed. That includes `n_a` controls, and heuristic FAILs that section 6 ("Checks that need administrator input", `unresolved_block`) doesn't list. So the summary number and the section 6 table disagree.
- **Verified:** by reading.

### 17. Provisional (heuristic) FAILs are counted in findings totals and the legacy score
- **Where:** `backend/app/analysis/engine.py:181`. The findings list takes every `FAIL`, whatever its assurance.
- **What:** `total_findings`, `critical_count`/`high_count` and the legacy `score` include heuristic FAILs. These numbers are shown by:
  - `/assistant/summary` (`routes/assistant.py:174` and `:183`)
  - the assistant's chat context (`routes/assistant.py:64`)

  This contradicts the stated rule that provisional verdicts are never counted. The PDF and the UI filter by assurance correctly.
- **Verified:** by reading.

---

## Low

### 18. Cisco banners with the `^C` delimiter keep a stray `C`
- **Where:** `backend/app/parsers/cisco_ios.py:274-296`.
- **What:** The delimiter is captured as one character (`(.)`), so `^C` is read as `^`.
  - `banner login ^CAuthorized only^C` is stored as `"CAuthorized only"` (reproduced).
  - In the multi-line form, any text after `^C` on the first line is dropped.

### 19. FastAPI validation errors are shown as "API error: 422"
- **Where:** `frontend/src/api/client.js:3-9`.
- **What:** Pydantic errors return `detail` as an array, which `errorMessage` ignores. An example is a port above 65535 in the Collect form, whose message is never shown.

### 20. The frontend never sends `X-API-Key`
- **Where:** `frontend/src/api/client.js`.
- **What:** Setting `API_KEY` on the backend breaks the whole UI with 401s. The README and docs already record this as a known gap. It's listed here so it isn't forgotten.

### 21. The download's object URL is revoked immediately after `click()`
- **Where:** `frontend/src/api/client.js:62-64`.
- **What:** Some browsers (Safari, older Firefox) can cancel the download when the URL is revoked synchronously. The usual fix is to defer the revoke with `setTimeout`.
- **Verified:** plausible, not reproduced.

### 22. SQLite migrations aren't atomic
- **Where:** `backend/app/db/database.py:231-233`.
- **What:** `executescript` commits statement by statement, and `user_version` is only bumped after the script finishes. If migration v2 (five `ALTER TABLE`s) fails partway, every restart re-runs it and fails with "duplicate column".

### 23. `DATABASE_URL` password encoding only handles `@`
- **Where:** `backend/app/db/database.py:161-171` (`_encode_password`).
- **What:** It only acts when the URL contains more than one `@`. A password pasted raw with `#`, `/` or `?` still breaks URL parsing.

### 24. `/assistant/explain` finds the finding by hostname only
- **Where:** `backend/app/api/routes/assistant.py:139-142`.
- **What:** If two uploaded configs share a hostname, the explanation always comes from the first one. Everywhere else the code uses `config_index` as the device identity.

### 25. `clearScanHistory` has no try/catch
- **Where:** `frontend/src/utils/history.js:222`.
- **What:** Every other history helper guards its `localStorage` access. This one throws where storage is blocked, such as some private modes.

### 26. Garbled `.gitignore` line
- **Where:** `.gitignore`. The line reads `ign NetAuditAI frontend*`.
- **What:** It looks like a half-pasted pattern. It ignores files starting with `ign NetAuditAI frontend`, which is probably not what was meant.

---

## Checked and not a bug
- **IPv4-mapped IPv6 SSRF bypass** (`::ffff:169.254.169.254`): refused on Python 3.10.11 (tested).
- **`_control_outcome` reading only `results[0]`:** safe, because non-FAIL outcomes always produce a single result.
- **`asserted_candidate` with a non-statement line:** guarded (it raises `LookupError`, which becomes a 404).
- **Markdown renderer:** it builds only React elements, so there is no HTML injection path.
