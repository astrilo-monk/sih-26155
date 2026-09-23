# lastmin.md

Last-mile coding work before submission, as prompts. One item per section: paste the **Prompt**
block into a fresh session, in order. Each prompt is self-contained and states what *not* to build.

Ordered by evaluator-visible value ÷ effort. Tier 1 is roughly half a day; Tier 2 is two controls.

House rules every prompt inherits (they are why this project is credible -do not let an agent
break them):

- Never report something the configuration does not state. No invented serials, no guessed versions.
- Decisive (`parser` / `confirmed` / `default`) and provisional (`heuristic` / `ai_verified`) never mix:
  provisional results change no posture, coverage, finding count or remediation.
- Absence is never a PASS -it is `NOT_CONFIGURED`.
- No secret is ever stored, printed or sent to AI.
- Leave one runnable check per non-trivial change. No new frameworks, no new dependencies.

---

## Tier 1

### 1. Commit the guided path

No code left -[Guide.jsx](frontend/src/app/Guide.jsx), [Guide.test.jsx](frontend/src/app/Guide.test.jsx)
and the [AppShell.jsx](frontend/src/app/AppShell.jsx) / [Upload.jsx](frontend/src/app/Upload.jsx) wiring
are finished and the suite is green (83 tests, 15 files).

**Prompt:**

> Commit the guided-path work: `frontend/src/app/Guide.jsx`, `frontend/src/app/Guide.test.jsx` and the
> modified `AppShell.jsx` and `Upload.jsx`. Run `npm test` in `frontend/` first and only commit if it is
> green. One commit, message in the style of the existing history (`feat: ...`, imperative, no body
> unless something needs explaining). Do not refactor anything while you are in there.

---

### 2. Wire the three dead AI endpoints into the UI

`client.js` has `explain`, `summary` and `chat` ([client.js:128-145](frontend/src/api/client.js#L128));
**no JSX calls any of them.** The PS headline is "AI-Driven" and a judge can currently finish a whole
demo without seeing AI. Cheapest honest fix: one explain button on a finding.

**Prompt:**

> In `frontend/`, add an "Explain this" button to the finding drawer (`src/app/FindingDrawer.jsx`) that
> calls the existing `explain` method in `src/api/client.js`
> (`GET /api/assistant/explain/{scan_id}/{rule_id}/{hostname}`) and renders the returned text in the
> drawer, below the evidence.
>
> Constraints:
> - Reuse the existing loading / error primitives in `src/components/ui/primitives.jsx` -do not invent
>   new ones.
> - The explanation is commentary, not evidence: label it as AI-written, and it must not change any
>   status, severity, posture or count shown anywhere.
> - Hide or disable the button when AI is unavailable. `GET /api/assistant/status` already reports this;
>   check whether the app already fetches it before adding a second fetch.
> - Handle the failure path: no key, quota exhausted, request error -a quiet inline message, never a
>   crash and never a silent swallow.
>
> Do NOT build a chat view and do NOT wire the `summary` endpoint. Add one test in
> `FindingDrawer.test.jsx` with the client mocked: button click renders the explanation, and a failed
> call renders the error. Leave `chat` and `summary` in the client untouched.

---

### 3. Read the FortiOS `#config-version` header

[cisco_ios.py:74](backend/app/parsers/cisco_ios.py#L74) fills `device.os_version`; the FortiGate parser
fills nothing, so section 1 of every FortiGate report says "not stated in the configuration" while the
model and firmware are sitting in line 1 of a real export. This is the PS "device identification,
including hardware details" bullet, answered from the file.

**Prompt:**

> Real FortiGate exports begin with a comment header, e.g.
> `#config-version=FGT60D-6.00-FW-build0163-180510:opmode=0:vdom=0:user=admin`, and sometimes
> `#buildno=0163` / `#global_vdom=1` lines. `backend/app/parsers/fortinet.py` currently ignores all of it.
>
> Parse that header and set what it states on the normalized device: the platform/model token
> (`FGT60D`) and the firmware version with build (`6.00 build0163`). Check the exact field names on
> `Device` in `backend/app/models/normalized.py` and use what is there; add a field only if there is
> genuinely nowhere to put the model, and if you do, check `backend/app/models/field_catalog.py` -
> it introspects the dataclasses, so a new field enters the adaptive vocabulary and may need a value rule.
>
> Constraints:
> - If the header is absent or does not match, set nothing. No guessing from other lines.
> - This is identification only: it must not create a SecurityFact, influence vendor detection, change
>   parse coverage, or select a parser. Confirm detection and coverage are untouched by reading
>   `backend/app/parsers/detector.py` and `coverage.py` before you edit.
> - `sample/fortigate-1.cfg` has no such header. Add the header to a test fixture rather than editing the
>   sample, unless the sample is meant to look like a real export -say which you chose and why.
> - The PDF report reads `device`, so check `identification_block` in `backend/app/reporting/report.py`
>   shows the model. If the note at line 104 now overstates what is missing, narrow it to serial and
>   chassis only -do not delete it.
>
> One test in `backend/tests/` for the header being parsed and one for a config without it. Run
> `python -m pytest tests -q` in `backend/`.

---

### 4. API key and configurable CORS

[main.py:13](backend/app/main.py#L13) hardcodes `allow_origins=["*"]` and no endpoint has auth. The
sponsor is NTRO; an unauthenticated security auditor is the one gap a judge will say out loud.

**Prompt:**

> In `backend/`, add optional API-key auth and make CORS configurable.
>
> - Add `API_KEY` and `CORS_ORIGINS` to `backend/app/config.py`, following exactly how the existing
>   settings there are declared and defaulted.
> - When `API_KEY` is unset (the default), every endpoint behaves as it does today -the demo must not
>   need a key. When it is set, require it as an `X-API-Key` header on every `/api` route and return
>   401 otherwise.
> - Use one FastAPI dependency applied at the router or app level. Do not decorate 30 route functions,
>   and do not add a dependency package -`fastapi.Security` / `APIKeyHeader` is already available.
> - `CORS_ORIGINS` defaults to the current `["*"]` so nothing breaks; a comma-separated value narrows it.
> - Compare the key with `secrets.compare_digest`, and never log it.
> - Document both in the README settings table and `backend/.env.example`, in the existing style.
>
> Two tests: a request with no key configured succeeds; with a key configured, a wrong key gives 401 and
> the right key succeeds. Check `backend/tests/conftest.py` for how the app and client are built and
> follow it, so the other ~1020 tests keep passing. Run the full suite.

---

## Tier 2 -two controls, not ten

Both slot into the existing chain, so each is small and lands in all four framework views for free.
Adding a control touches, in order: a predicate in [predicates.py](backend/app/facts/predicates.py) →
a normalized field the parsers fill → a `FIELD_PREDICATES` row → a judge in
[judges.py](backend/app/controls/judges.py) (+ its `JUDGES` entry) → a `Control` in
[catalog.py](backend/app/controls/catalog.py) with real framework mappings → lexicon terms in
[lexicon.py](backend/app/facts/lexicon.py) for the generic path → a recipe in
[recipes.py](backend/app/remediation/recipes.py) if a deterministic fix is honest.

Read that whole chain for one existing control (LOG-001 is the cleanest) before writing either of these.

### 5. LOG-003 -administrative access accounting

The PS says verbatim *"logging all administrative access."* LOG-001 covers syslog destinations; nothing
covers whether admin commands and logins are actually recorded.

**Prompt:**

> Add control `LOG-003`, "Administrative access and commands not logged", to the backend: does the device
> record administrative logins and configuration commands?
>
> Follow the existing chain end to end -trace `LOG-001` from predicate to judge to catalog entry to
> recipe first, and mirror it. Specifically:
> - New predicate in `app/facts/predicates.py` with a value convention comment like its neighbours.
> - The evidence per vendor: Cisco IOS `aaa accounting commands <level> <list> start-stop group ...` and
>   `aaa accounting exec`; FortiOS `config log setting` / `set local-out`, and event logging with admin
>   events enabled. Read what each parser already builds in `app/parsers/cisco_ios.py` and `fortinet.py`
>   and add only the fields the control needs.
> - `FIELD_PREDICATES` row(s) so an administrator can teach this setting on an unparsed dialect.
> - Judge in `app/controls/judges.py`: accounting present and pointing somewhere → PASS; explicitly off →
>   FAIL; nothing found on a confirmed vendor → NOT_CONFIGURED, never PASS. Severity HIGH, category
>   "logging", kind REQUIREMENT.
> - Framework mappings in `app/controls/catalog.py`. Every id must be real and current: NIST SP 800-53
>   Rev. 5 AU-family ids for auditable events and content (check they are not withdrawn), the Network
>   Device Management SRG requirement whose wording actually matches, and ISO/IEC 27001:2022 A.8.15.
>   A CIS item only if you can confirm it exists in the exact benchmark version already cited in that
>   file -otherwise no CIS mapping, per the module docstring. State your source for each id in the
>   commit message.
> - Lexicon terms so the generic path can recognize accounting lines in other dialects.
> - A Cisco recipe only if adding accounting lines is safe without knowing the AAA server config. If it
>   is not, register no recipe and let it report as manual review -that is the correct outcome, not a
>   gap to paper over.
>
> Tests: judge PASS / FAIL / NOT_CONFIGURED, and one end-to-end scan assertion on a fixture config.
> Run the full backend suite; `docs/detection-rules.md` lists the controls, so update it and the "15
> controls" counts in `README.md` and `docs/`.

### 6. CRYPTO-002 -management TLS version

`sample/fortigate-1.cfg` line 3 already carries `set admin-https-ssl-versions tlsv1-2` and nothing reads
it. The PS asks for "enforcing strong cryptographic suites"; CRYPTO-001 only covers IPsec, so the
management plane is the uncovered half.

**Prompt:**

> Add control `CRYPTO-002`, "Weak TLS version for management access", to the backend: does HTTPS/TLS
> management refuse TLS below 1.2?
>
> Same chain as LOG-003 -read `CRYPTO-001` (a THRESHOLD control) end to end first and mirror it.
> - New predicate; value is the minimum accepted TLS version as stated by the configuration.
> - FortiOS evidence: `set admin-https-ssl-versions` in `config system global` (already present in
>   `sample/fortigate-1.cfg`). Cisco IOS evidence: `ip http tls-version` / `ip http secure-server`
>   ciphersuite lines -only read what the IOS grammar in `app/parsers/coverage.py` already accepts, and
>   if adding a root keyword there changes parse coverage, say so rather than silently shifting the
>   0.7 threshold behaviour.
> - THRESHOLD judge: >= TLS 1.2 PASS, below FAIL (HIGH), value present but unparseable UNKNOWN, absent on
>   a confirmed vendor NOT_CONFIGURED. Category "cryptography".
> - Framework mappings with verified ids only: NIST SP 800-53 Rev. 5 SC-8 / SC-8(1) and the AC-17(2)
>   family as applicable, the matching NDM SRG requirement, ISO/IEC 27001:2022 A.8.24, and a CIS
>   FortiGate item only if it exists in the benchmark version already cited.
> - Lexicon terms for TLS/SSL version wording across dialects.
> - Recipes: FortiGate can be fixed deterministically -reuse `_forti_global_recipe` in
>   `app/remediation/recipes.py` to set `admin-https-ssl-versions tlsv1-2 tlsv1-3`. Cisco only if the
>   change cannot lock anyone out; otherwise no recipe.
>
> Tests: threshold judge at 1.0 / 1.2 / missing, plus the FortiGate recipe verified by the existing
> rescan path (the same way other recipe tests do it -do not write a new harness). Full suite, and
> update the control count and `docs/detection-rules.md`.

---

## Explicitly not doing

Named here so nobody "helpfully" adds them the night before.

| Skipped | Why |
|---|---|
| A third dedicated parser | The generic path + recognizers *is* the architecture answer; a third parser argues against your own thesis |
| ~~Netmiko / NAPALM live collection~~ | Built (`app.collect`, `POST /api/collect`), but **off unless `LIVE_COLLECTION_ENABLED=true`** -so the default deployment still never touches a device, and the security story is unchanged |
| Zip / archive upload | Multi-file upload already works (`POST /api/scan` takes a file list) |
| Assistant chat view, `summary` endpoint UI | Unchecked stretch items; the explain button in item 2 covers the AI demo |
| Historical scan comparison | Unchecked stretch; nothing in the PS asks for it |
| More seed dialects | 61 recognizers across 8 dialects already exceeds what a 2-minute video can show |
| More controls beyond these two | Framework breadth past this point is invisible to a judge and costs the demo |

## Five-minute README fixes

Not code, but it is the first thing read, and it currently undersells the project.

- "25 reviewed recognizers for five unparsed dialects" → **61 across 8** (adds Extreme Networks EXOS,
  HPE Aruba AOS-CX, Check Point Gaia). The same wording appears in `docs/seed-knowledge.md` and the
  "Known limitations" section.
- "81 passed" → **83 passed**.
- The control count wherever it says 15, after Tier 2.
