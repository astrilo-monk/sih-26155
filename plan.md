# NetAuditAI Adaptive Parsing Implementation Plan

## Goal

Add adaptive, vendor-agnostic configuration parsing without breaking the
existing deterministic compliance engine.

The final pipeline is:

```text
Config
  ↓
Vendor Detector
  ↓
Known Vendor Parser OR Adaptive Path
  ↓
NormalizedConfig
  ↓
Adaptive Service
  ├── Security Relevance Filter
  ├── Learned Mapping Matcher
  ├── Gemini Fallback
  ├── Confidence Validation
  └── Safe Normalization
  ↓
NormalizedConfig
  ↓
Existing Compliance Engine
  ↓
Findings / Score
  ↓
Existing Remediation
```

The system does NOT retrain Gemini. It learns by persisting administrator-
confirmed syntax-to-concept mappings.

---

# Core Architectural Rules

1. Existing deterministic compliance rules remain untouched.
2. Existing Cisco IOS and FortiGate parsers remain responsible for syntax
   they already understand.
3. Do not create a hardcoded parser class for every new vendor.
4. Do not put Gemini calls inside vendor parsers.
5. Do not put database queries inside parsers.
6. Do not put compliance decisions inside Gemini.
7. The frontend must never call Gemini or SQLite directly.
8. Learned mappings are checked before Gemini.
9. Gemini is the fallback for genuinely unknown syntax.
10. Admin-confirmed mappings are persisted.
11. Confirmed mappings must never be silently overwritten by AI.
12. Unknown or uncertain values remain unknown rather than being guessed.
13. The adaptive layer must work for known and unknown vendors.
14. The compliance engine receives the same `NormalizedConfig` regardless
    of where a value originated.
15. Preserve evidence for every adaptive value:
    original line, line number, interpretation, source, confidence, and
    final normalized value.

---

# Final Architecture

```text
                         CONFIG FILE
                             │
                             ▼
                     ┌────────────────┐
                     │ Vendor Detector│
                     └───────┬────────┘
                             │
                 ┌───────────┴───────────┐
                 │                       │
          Known vendor             Unknown vendor
                 │                       │
                 ▼                       ▼
          Existing Parser         Adaptive Parser Path
                 │                       │
                 └───────────┬───────────┘
                             ▼
                    NormalizedConfig
                             │
                             │ unknown security lines
                             ▼
                  ┌──────────────────────┐
                  │ Adaptive Service     │
                  │                      │
                  │ 1. Relevance Filter │
                  │ 2. Learned Matcher   │
                  │ 3. Gemini Fallback   │
                  │ 4. Confidence        │
                  │ 5. Validation        │
                  │ 6. Normalization     │
                  └──────────┬───────────┘
                             │
                             ▼
                    NormalizedConfig
                       enriched safely
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Existing Compliance  │
                  │ Engine               │
                  └──────────┬───────────┘
                             ▼
                       Findings / Score
                             │
                             ▼
                        Remediation
```

## Suggested Backend Structure

Inspect the existing repository structure first and follow its conventions.
Do not blindly duplicate modules.

```text
backend/app/

├── parsers/
│   ├── cisco_ios.py
│   ├── fortinet.py
│   └── detector.py
│
├── models/
│   └── normalized.py
│
├── adaptive/
│   ├── service.py
│   ├── interpreter.py
│   ├── matcher.py
│   ├── mapper.py
│   ├── schemas.py
│   └── relevance.py
│
├── ai/
│   ├── client.py
│   └── prompts.py
│
├── db/
│   ├── ...
│   └── mappings.py
│
├── api/
│   └── routes/
│       └── adaptive.py
│
├── analysis/
│   ├── engine.py          # unchanged
│   └── rules/             # unchanged
│
└── remediation/
    └── engine.py          # unchanged
```

---

# Phase 1 — Unknown-Line Detection

## Architecture Change

Current:

```text
Vendor Detector
      ↓
Vendor Parser
      ↓
NormalizedConfig
      ↓
Compliance Engine
```

New:

```text
Vendor Detector
      ↓
Vendor Parser
  ├── recognized syntax → existing normalization
  └── unknown syntax → UnrecognizedLine collection
                              ↓
                       Security relevance filter
                              ↓
                       NormalizedConfig
                              ↓
                       Adaptive pipeline
```

Do not put AI logic inside the Cisco or FortiGate parsers.

The parsers are responsible only for:

1. Recognizing syntax they already understand.
2. Capturing syntax they do not understand.

The adaptive system is a separate layer.

## Implementation Prompt

```text
CONTEXT

NetAuditAI backend uses FastAPI and already has working Cisco IOS and
FortiGate parsers plus a deterministic compliance engine.

This phase adds the foundation for adaptive parsing.

DO NOT modify:
- app/parsers/cisco_ios.py
- app/parsers/fortinet.py
- app/analysis/
- app/remediation/engine.py

Do not change existing parsing behavior, rule logic, scoring, or
remediation.

FIRST

Inspect:
- app/parsers/cisco_ios.py
- app/parsers/fortinet.py
- app/models/normalized.py
- existing parser tests

Identify where parser input lines currently fall through without being
recognized. Report the relevant parse-loop behavior before implementing.

TASK

1. Add an `UnrecognizedLine` model containing:
   - raw_line
   - line_number
   - vendor
   - context_before
   - context_after

2. Add:
   `unrecognized_lines: list[UnrecognizedLine]`
   to `NormalizedConfig`.

3. Capture parser lines that are not recognized by the existing parser.

4. Apply a cheap SECURITY-RELEVANCE-FILTER before adding a line to
   `unrecognized_lines`.

   Initial case-insensitive indicators:

   ssh, telnet, snmp, password, secret, logging, syslog, ntp, acl,
   access-list, aaa, banner, crypto, ipsec, vpn, cdp, lldp, http,
   timeout, community, radius, tacacs

5. The keyword filter is ONLY a candidate-generation mechanism.
   It must NOT determine compliance.

6. Irrelevant structural lines such as ordinary interface descriptions,
   IP addressing, VLAN configuration, and routing statements should not
   enter the adaptive queue.

7. Preserve the original raw line and exact line number.

8. Preserve all existing recognized parser output exactly as before.

9. If vendor detection is unavailable, use `"unknown"`.

10. Do not call Gemini in this phase.

TESTING

Add tests for:

A. Recognized line → existing behavior unchanged.
B. Unknown security-relevant line → captured.
C. Unknown irrelevant line → not captured.
D. Exact line number.
E. Surrounding context.
F. Correct vendor value.

Run the complete backend test suite.
```

---

# Phase 2 — Gemini Interpretation

## Architecture Change

Introduce a dedicated adaptive interpretation layer.

```text
Parser
  ↓
NormalizedConfig
  ↓
Adaptive Interpretation Service
  ↓
AI Interpretation Results
  ↓
Confidence / Validation
  ↓
NormalizedConfig enrichment
  ↓
Compliance Engine
```

Gemini must not be embedded in vendor parsers.

## Implementation Prompt

```text
CONTEXT

Phase 1 now produces security-relevant `unrecognized_lines`.

The repository already has Gemini integration.

FIRST inspect:
- app/ai/client.py
- app/ai/prompts.py
- app/config.py
- installed google-genai dependency/version
- existing assistant tests

Use the existing Gemini client and calling conventions.

DO NOT introduce:
- Groq
- OpenAI
- another AI provider
- another Gemini client implementation

TASK

1. Create a dedicated adaptive interpretation service.

2. For EACH CONFIG, send ONE batched Gemini request containing all
   security-relevant unrecognized lines.

   Never make one API request per line.

3. Return one structured result per input line:

   - line_number
   - raw_line
   - likely_vendor
   - security_concept
   - normalized_field
   - extracted_value
   - confidence
   - reasoning

4. `normalized_field` must correspond to an actual field supported by
   `NormalizedConfig` or be `"unknown"`.

5. `security_concept` should be vendor-independent where possible.

6. Gemini performs semantic interpretation only.

   Gemini MUST NOT:
   - determine compliance
   - create PASS/FAIL findings
   - modify scoring
   - generate remediation
   - override deterministic rules

7. Use Gemini structured JSON / response schema supported by the installed
   google-genai version.

8. Validate responses with Pydantic.

9. Reject malformed responses safely.

10. Every Gemini call requires exception handling and a reasonable timeout.

11. If Gemini fails, times out, returns invalid JSON, or produces an unusable
    interpretation:
    - mark the affected lines `ai_unavailable`
    - preserve original unrecognized lines
    - continue the core scan
    - do not fabricate an interpretation

12. AI interpretation must be optional enrichment. The deterministic scan
    must still work when Gemini is unavailable.

13. Put interpretation schemas in:
    app/ai/interpretation_schemas.py

TESTING

Mock Gemini. Do not call the real API.

Test:
A. Valid batched response.
B. Malformed response.
C. Gemini exception.
D. Gemini timeout.
E. Multiple lines produce exactly one Gemini request.
F. Invalid/invented normalized fields are rejected.

Run the full backend test suite.
```

---

# Phase 3 — Confidence + Safe Normalization

## Architecture Change

Do not let the Gemini client directly mutate `NormalizedConfig`.

Use:

```text
AI Interpretation
       ↓
Interpretation Validator
       ↓
Confidence Decision
       ↓
Safe NormalizedConfig Enrichment
       ↓
Compliance Engine
```

Conceptually:

```text
ParsedConfig
    +
AIInterpretation
    ↓
AdaptiveMapper
    ↓
NormalizedConfig
```

`AdaptiveMapper` is responsible for converting validated AI output into
actual `NormalizedConfig` fields.

## Implementation Prompt

```text
CONTEXT

Phase 2 produces validated AI interpretations with confidence scores.

The existing deterministic compliance engine remains the sole authority
for PASS/FAIL.

DO NOT modify:
- app/analysis/rules/
- app/analysis/engine.py
- scoring logic
- remediation logic

TASK

Implement confidence-based interpretation.

TIERS

HIGH:
>= 0.85

MEDIUM:
>= 0.50 and < 0.85

LOW:
< 0.50

HIGH

Auto-map ONLY when:
- normalized_field is valid
- extracted_value matches the field's expected type
- interpretation has sufficient evidence
- schema validation succeeds

If valid:
- enrich NormalizedConfig
- mark source `ai_auto_mapped`
- preserve line, interpretation, confidence, and reasoning
- allow existing deterministic rules to evaluate it

If invalid, send to review instead.

MEDIUM

- retain proposed field/value
- mark `needs_review`
- expose confidence and interpretation
- DO NOT let it silently create a compliance PASS

LOW

- do not populate NormalizedConfig
- retain AI suggestion
- mark `needs_training`
- expose to Phase 4

IMPORTANT SAFETY RULE

An uncertain interpretation must never cause a vulnerable configuration to
appear compliant.

AUDITABILITY

Every AI-touched line must expose:
- raw line
- line number
- normalized field
- extracted value
- confidence
- confidence tier
- reasoning
- status
- source

TESTING

Mock:
1. Valid HIGH mapping.
2. Invalid HIGH mapping.
3. MEDIUM mapping.
4. LOW mapping.

Verify deterministic rules remain unchanged.

Run the complete backend test suite.
```

---

# Phase 4 — Admin Training UI

## Architecture Change

The frontend communicates only with FastAPI.

```text
Frontend
   ↓
FastAPI Adaptive API
   ↓
Adaptive Service
   ├── Interpreter
   ├── Mapper
   └── Persistence
          ↓
        SQLite
```

The frontend must never know about Gemini API keys, Gemini request format,
or SQLite implementation details.

## Implementation Prompt

```text
CONTEXT

Build the human-in-the-loop training interface.

Do NOT redesign the existing dashboard.

FIRST inspect:
- frontend/src/components/
- existing scan/result views
- RemediationView / RemediationQueue
- backend API conventions

Match the existing UI architecture and visual language.

BACKEND

Create endpoints to:
1. List unresolved interpretations for a scan.
2. Accept an interpretation unchanged.
3. Accept an edited interpretation.
4. Reject an interpretation.

Validate normalized fields against the actual NormalizedConfig schema.

FRONTEND

Add a focused Training / Adaptive Parsing panel or tab.

Display:
- original line
- line number
- surrounding context
- AI suggestion
- normalized field
- extracted value
- confidence
- reasoning

Actions:
- Accept
- Edit
- Reject

Accept/Edit:
→ create confirmed learned mapping through Phase 5.

Reject:
→ mark reviewed-but-unmapped.

Do not automatically retry rejected lines on every scan.

VALIDATION

Frontend:
- prevent empty/invalid submissions.

Backend:
- validate normalized field
- validate extracted value type
- reject malformed mappings

TESTING

Backend:
- accept
- edit
- reject
- invalid field
- invalid value
- already-reviewed item

Frontend:
- render queue
- accept
- edit
- reject
- validation
```

---

# Phase 5 — Learned Mapping Database

## Architecture Change

Introduce the persistent Adaptive Knowledge Layer.

```text
Unknown Line
    ↓
Learned Mapping Matcher
    │
    ├── reliable match → normalize
    │
    └── no match → Gemini
                     ↓
               Admin confirmation
                     ↓
                   SQLite
```

The key conceptual separation is:

```text
CONCEPT
  = what the configuration means

PATTERN
  = how a vendor expresses it

MAPPING
  = relationship between pattern and normalized concept
```

Example:

```text
Concept:
    session_timeout

Pattern A:
    exec-timeout 5

Pattern B:
    admin idle-timeout 300

Both:
    normalized_field = session_timeout
```

Vendor is metadata, not the identity of the concept.

## Implementation Prompt

```text
CONTEXT

Implement persistent storage for administrator-confirmed adaptive parsing
mappings.

Use SQLite and follow the project's existing database conventions.

IMPORTANT

Do NOT make vendor the primary identity of a mapping.

Schema should contain approximately:

- id
- concept
- normalized_field
- vendor (nullable)
- command_pattern
- extraction_method
- expected_value_type
- confidence
- confirmed
- created_at
- updated_at

Adjust the exact schema if existing project architecture requires it.

TASK

1. Implement database initialization/migration using existing conventions.

2. Create a MappingRepository or equivalent persistence boundary.

3. Implement:
   - save_mapping
   - find_matching_mappings
   - update_mapping
   - disable_mapping

4. When admin confirms an interpretation, persist it.

5. During future scans:

   STEP 1:
   Check confirmed mappings BEFORE Gemini.

   STEP 2:
   If a reliable mapping matches, extract and normalize.

   STEP 3:
   If no reliable mapping matches, fall back to Gemini.

6. Validate patterns before persistence.

7. Do not allow unsafe unrestricted regex from AI.

8. Never silently overwrite a confirmed mapping.

9. AI cannot modify confirmed mappings.

10. Explicit administrator editing may update/deactivate mappings.

11. If multiple mappings match ambiguously, do not guess. Send to review.

12. Prefer concept-level reuse across vendors.

TESTING

A. Save mapping.
B. Retrieve mapping.
C. Match it on a later scan.
D. Verify Gemini is not called for a reliable match.
E. Learn syntax from Vendor A.
F. Scan Vendor B with similar syntax.
G. Surface Vendor A mapping as a candidate concept/pattern.
H. Confirmed mapping cannot be silently overwritten.
I. Ambiguous mappings go to review.

Run the complete backend test suite.
```

---

# Phase 6 — Final Adaptive Vendor Integration

## Architecture Change

All vendor-independent adaptive behavior is centralized in one service.

Recommended conceptual structure:

```text
                  ┌────────────────────┐
                  │    AdaptiveService │
                  └─────────┬──────────┘
                            │
          ┌─────────────────┼─────────────────┐
          ↓                 ↓                 ↓
    RelevanceFilter   MappingMatcher    GeminiInterpreter
          │                 │                 │
          └─────────────────┼─────────────────┘
                            ↓
                     ConfidenceValidator
                            ↓
                       AdaptiveMapper
                            ↓
                     NormalizedConfig
                            ↓
                    Compliance Engine
```

This is preferable to scattering adaptive logic across individual
vendor parsers.

## Implementation Prompt

```text
CONTEXT

This is the final integration phase.

The final adaptive pipeline must be:

UNKNOWN VENDOR CONFIG
        ↓
UNKNOWN LINE DETECTION
        ↓
SECURITY RELEVANCE FILTER
        ↓
CONFIRMED LEARNED MAPPINGS
        ↓
GEMINI FALLBACK
        ↓
CONFIDENCE / VALIDATION
        ↓
NormalizedConfig
        ↓
EXISTING DETERMINISTIC RULES
        ↓
FINDINGS + SCORE

TASK

1. Route vendors without dedicated parsers through the adaptive path.

2. Do NOT create another hardcoded vendor parser.

3. Apply confirmed learned mappings first.

4. Send only unresolved security-relevant syntax to Gemini.

5. Apply HIGH-confidence interpretations only after schema/type validation.

6. MEDIUM requires review.

7. LOW remains unknown and enters training.

8. Never fabricate normalized values.

9. Never allow uncertain interpretation to produce a false PASS.

10. Preserve:
    - original line
    - line number
    - interpretation
    - mapping source
    - confidence
    - final normalized value

11. Existing compliance rules remain the sole compliance authority.

END-TO-END ACCEPTANCE TEST

FIRST SCAN

1. Feed unknown-vendor configuration containing unfamiliar SSH/Telnet syntax.
2. Assert unknown syntax is detected.
3. Assert relevance filter retains it.
4. Assert no learned mapping exists.
5. Assert exactly one batched Gemini request occurs.
6. Assert Gemini interpretation is produced.
7. Simulate admin confirmation.
8. Assert mapping is persisted.
9. Assert configuration normalizes correctly.
10. Assert existing compliance rule evaluates the normalized value correctly.

SECOND SCAN

Use another configuration containing the same syntax pattern.

Assert:
1. Unknown line is detected.
2. Confirmed learned mapping matches.
3. Value is extracted.
4. NormalizedConfig is populated.
5. Existing compliance rule evaluates it.
6. Gemini is NOT called.

REGRESSION

Run the original Cisco and FortiGate fixture suite.

Their existing:
- findings
- scores
- normalized fields
- remediation behavior

must remain unchanged.

DEMO REQUIREMENT

The final test must visibly demonstrate:

"Unknown syntax → AI interpretation → admin confirmation →
mapping persisted → same syntax recognized automatically later."

Do NOT claim that the system retrains Gemini.

The system learns by persisting confirmed syntax-to-concept mappings.
```

---

# Final Success Criteria

The implementation is complete when all of these are true:

- [ ] Existing Cisco/FortiGate behavior is unchanged.
- [ ] Unknown security-relevant syntax is captured.
- [ ] Irrelevant parser noise is filtered.
- [ ] Gemini receives one batched request per config.
- [ ] Gemini failure never breaks the core scan.
- [ ] AI output is schema-validated.
- [ ] Confidence determines whether interpretation is applied.
- [ ] Medium/low confidence cannot silently produce PASS.
- [ ] Admin can accept/edit/reject interpretations.
- [ ] Confirmed mappings persist in SQLite.
- [ ] Learned mappings are checked before Gemini.
- [ ] Mappings are not rigidly siloed by vendor.
- [ ] Confirmed mappings cannot be silently overwritten.
- [ ] Unknown vendors can use the adaptive path.
- [ ] Existing deterministic rules remain the compliance authority.
- [ ] First scan can learn a syntax.
- [ ] Second scan recognizes the same syntax without Gemini.
- [ ] Full existing test suite remains green.

## Core SIH Demonstration

The strongest demonstration is:

```text
Unknown Vendor
      ↓
Unfamiliar SSH/Telnet syntax
      ↓
AI identifies meaning
      ↓
Admin confirms
      ↓
Mapping saved
      ↓
Compliance scan succeeds
      ↓
Upload second config
      ↓
Same syntax recognized
      ↓
NO AI CALL
      ↓
Compliance scan succeeds
```

This demonstrates **adaptive learning**, not model retraining.
