# AI Layer Design

This document describes how AI (Groq, model `openai/gpt-oss-120b`) is used in NetAuditAI. All calls go through `backend/app/ai/client.py`.

## AI vs. Deterministic Logic

**AI is NOT used to decide whether a configuration is compliant.** Findings come only from the deterministic Python rules engine, which runs on the `NormalizedConfig` model.

AI is used in two places:

1. **Assistant:** explanations, summaries and chat about findings that already exist.
2. **Adaptive interpretation:** translating configuration lines that no parser understood into normalized fields. The deterministic rules then evaluate those fields.

## 1. Assistant

Once the rules engine has produced findings, the assistant endpoints (`/api/assistant/*`) can send finding or scan context to the AI for:

* **Plain-English explanations** of a finding
* **Scan summaries** of the overall result
* **Chat** about a scan ("Why is MGMT-001 failing?")

## 2. Adaptive Interpretation (unknown vendors and unfamiliar syntax)

Lines that no parser recognized, and every line of an unknown-vendor config, go through `backend/app/adaptive/`:

1. **Capture** (`capture.py`, `context.py`): the unrecognized line is recorded with its block path (e.g. `config system > edit admin`). The path is worked out from braces, `config`/`edit`/`end` blocks and indentation, with no vendor-specific parser.
2. **Relevance filter** (`relevance.py`): lines that are not security-relevant are dropped.
3. **Learned mappings** (`matcher.py`): lines matching an administrator-confirmed mapping are normalized without an AI call. Previously rejected lines are never re-sent.
4. **AI interpretation** (`interpreter.py`): the remaining lines are sent 10 at a time using strict JSON-schema output (temperature 0, fixed seed). The AI may only pick a field from the controlled vocabulary in `backend/app/models/field_catalog.py`, or answer `unknown`. It must cite the evidence text. Failed batches are retried once and then split in half; a daily-quota error stops further calls for that scan.
5. **Validation and confidence** (`mapper.py`):
   * the cited evidence must appear in the line
   * string and list values must be present
   * on/off answers must match the line's polarity (negations such as `no`, `disable` flip it)
   * HIGH (≥ 0.85) with valid evidence is applied automatically
   * MEDIUM, LOW, contradicted, or conflicting-with-a-learned-mapping results go to the Training queue
6. **Training** (frontend Training tab, `/api/adaptive/*`): an administrator accepts, edits or rejects each item. Accepted mappings are stored in SQLite and reused on later scans.

### Vendor handling

`device.vendor` is set only by the deterministic detector. For unknown configs it stays `unknown`. The AI's vendor guesses from validated lines are summarized as **vendor evidence** (`identified`, `conflicting` or `unknown`). This is reported in the scan result but **never** used to enable vendor-specific rules.

### AI unavailable

If there is no API key, or every key is rate-limited or out of quota, the affected lines are marked **AI unavailable**. This is a separate status from LOW confidence. The scan still completes, the score is flagged provisional, and the lines can be mapped manually in the Training tab.

## Key rotation

Keys are tried in order: `GROQ_API_KEY`, then `GROQ_API_KEY_1` .. `_4`.

| Error | Behaviour |
|-------|-----------|
| 429 rate limit | try next key |
| 401 / 403 / 404 (key rejected, no model access) | try next key |
| 429 daily quota on every key | report `quota_exhausted`, stop calling for this scan |
| 400, timeout, network error | fail this request (interpreter retries / splits) without trying other keys |

Keys that belong to the same Groq organization share one daily quota, so adding keys from the same account does not increase capacity. Key material is never logged.

## Remediation Generation: Deterministic Templates

**AI does not generate remediation commands.** Fixes come from deterministic, vendor-specific templates in `remediation/engine.py`, because an invented command could disrupt real network equipment.

## Fallback Behavior

Without an API key, or when Groq is unavailable:
* Detection, scoring and deterministic remediation still work.
* Finding explanations and summaries fall back to static text.
* Adaptive lines are marked AI unavailable, and confirmed learned mappings still apply.
