# AI Layer Design

This document describes how AI (Groq, model `openai/gpt-oss-120b`) is used in NetAuditAI. All calls go through `backend/app/ai/client.py`.

## AI vs. Deterministic Logic

**AI is NOT used to decide whether a configuration is compliant.** Findings, posture, coverage and remediation come only from the deterministic engine. An AI answer is a proposal that stays UNKNOWN until an administrator confirms it.

AI is used in four places:

1. **Assistant:** explanations, summaries and chat about findings that already exist.
2. **AI judge** (`backend/app/ai/judge.py`, unknown vendors): the only AI interpretation path by default.
3. **Remediation candidates** (`backend/app/ai/remediation.py`, unconfirmed vendors, on request): command *text* for
   a human to review -never a verdict, never applied.
4. **Legacy line interpretation** (confirmed Cisco / FortiGate only, `adaptive_ai_for_known_vendors`, off by default): review-queue suggestions, never applied without an administrator.

## 1. Assistant

Once the rules engine has produced findings, the assistant endpoints (`/api/assistant/*`) can send finding or scan context to the AI for:

* **Plain-English explanations** of a finding
* **Scan summaries** of the overall result
* **Chat** about a scan ("Why is MGMT-001 failing?")

## 2. AI Judge (unknown vendors)

Unknown-vendor configs are read by recognizers (administrator-confirmed), learned mappings and lexicon heuristics first. The judge then escalates what they could not decide:

1. **Targets**: UNKNOWN controls first, then NOT_CONFIGURED controls as evidence discovery (marked `discover` in the prompt), most severe first. At most `ai_judge_max_calls_per_scan` calls, 4 controls per call. A control is sent only with lines about one of its settings: lines the lexicon reads, or at most 3 lines naming related vocabulary. Limits, counters and lockouts never count as related. A config with no such line sends nothing, so absence is never asked about.
2. **Excerpt**: each target line's tokenizer scope (its block, nearest 15 lines, plus enclosing headers), never the whole config. The whole config is redacted first. Every excerpt and the prompt are then scrubbed of every known secret.
3. **Verifier** (deterministic, per proposal):
   * the control was asked, and the predicate is one it needs
   * every line ref exists
   * the quoted evidence is on a cited line
   * all cited lines sit in one tokenizer scope
   * every cited setting line supports the value. A line the lexicon reads must be read the same way. An unfamiliar line (`operator lock-after 10 minutes`) must name related vocabulary for the setting and state the value itself: its polarity, the number with a unit word written on the line, or an address or hostname token.
4. **Result**: verified proposals become AI_VERIFIED facts bound to the asking control; no other control reads them. The control reports UNKNOWN, with a proposed PASS / FAIL when the fact decides it. Some facts do not decide it: an NTP server without authentication gives no proposal. Posture, coverage, score, findings and remediation ignore AI facts. An answer with no verified proposal is never cached, and a cached answer is re-verified.
5. **Training**: verified lines appear in the provisional queue. Confirming one saves a recognizer, which is decisive from then on. Rejecting one drops the line. Hallucinated or unverified citations never reach the queue.

## 3. Remediation Candidates (unconfirmed vendors, on request)

**Not AI: the derived candidate.** The Fix page's *Fix it for me* asks no model anything. `candidates.derive` takes
the lines the decisive FAIL cites, removes them from a copy and re-reads it with the generic engine; the text it
shows is built from the configuration's own block path and keywords. It runs with AI switched off, and the AI path
below is only for what it refuses (a control that needs a setting **added**, or a change it cannot state safely).

A device whose vendor is not confirmed has no deterministic recipe, so the Fix page can also ask for a **candidate
command** instead of showing a dead end. One request, for one control, only when the administrator presses the
button:

1. **Context** -the minimum the question needs: the control id, its question, the vendor-neutral recommendation the
   deterministic engine already produced, the vendor detection status (and an unverified look-alike, labelled as
   evidence only), the block path of the failing lines, and the tokenizer scope of those lines (the same excerpt rule
   the judge uses). The whole configuration is redacted first and the prompt is scrubbed of every known secret;
   the answer is scrubbed again before it is shown.
2. **Answer contract** -strict JSON schema: `control_id`, `candidate_command`, `explanation`, `confidence`
   (low / medium / high), `assumptions`. An answer with a missing field, an extra field, another control's id, a
   non-text command or an unknown confidence level is **refused**, not repaired.
3. **No authority** -the answer is command text and nothing else. It enters exactly the same review as a command an
   administrator typed: deterministic validation, simulation on a copy of the configuration where an effect can be
   derived, and administrator confirmation (see [architecture.md](architecture.md#10-remediation)). It is labelled
   "AI-generated candidate / not verified" until then, changes no control result, no posture and no coverage, and
   is never executed or applied. An AI proposal becomes downloadable -as a verified corrected *copy* of the
   uploaded configuration -only after deterministic verification passes; the AI never produces a file.
4. **Unavailable** -no key, no quota, a failed call or an unusable answer returns `503` with the reason; the manual
   path stays open. Nothing is invented on the AI's behalf.

## 4. Legacy Line Interpretation (confirmed vendors, opt-in)

The judge never escalates confirmed vendors, so this older path remains for them behind `adaptive_ai_for_known_vendors` (default off). Unknown-vendor configs never use it. Lines a Cisco / FortiGate parser did not recognize go through `backend/app/adaptive/`:

1. **Capture** (`capture.py`, `context.py`): the unrecognized line is recorded with its block path (e.g. `config system > edit admin`). The path is worked out from braces, `config`/`edit`/`end` blocks and indentation, with no vendor-specific parser.
2. **Relevance filter** (`relevance.py`): lines that are not security-relevant are dropped.
3. **Learned mappings** (`matcher.py`): lines matching an administrator-confirmed mapping are normalized without an AI call. Previously rejected lines are never re-sent.
4. **AI interpretation** (`interpreter.py`, only with the setting on): the remaining lines are sent 10 at a time using strict JSON-schema output (temperature 0, fixed seed). The AI may only pick a field from the controlled vocabulary in `backend/app/models/field_catalog.py`, or answer `unknown`. It must cite the evidence text. Failed batches are retried once and then split in half; a daily-quota error stops further calls for that scan.
5. **Validation and confidence** (`mapper.py`): the cited evidence must appear in the line; string and list values must be present; on/off answers must match the line's polarity. `AdaptiveService` never applies an interpretation: HIGH, MEDIUM, LOW, contradicted and conflicting results all go to the Training queue.
6. **Training** (Adaptive learning, `/api/adaptive/*`): an administrator accepts, edits or rejects each item. Accepted mappings are stored in the knowledge store (SQLite or Postgres) and reused on later scans; a line holding a secret is refused.

## What is persisted

* Recognizers and learned mappings (`learned_mappings`) -only after an administrator confirms; any text holding a secret is refused.
* Rejected lines (`rejected_lines`) -stored redacted and matched by their redacted form.
* AI judge cache (`ai_judge_cache`) -verified answers to redacted prompts, keyed by a hash; re-verified on every hit.

Scan results and uploaded configurations are kept in memory only.

### Vendor handling

`device.vendor` is set only by the deterministic detector. For unknown configs it stays `unknown`. The AI's vendor guesses are summarized as **vendor evidence** (`identified`, `conflicting` or `unknown`) for information only. It is **never** used to enable vendor-specific rules.

### AI unavailable

If there is no API key, or every key is rate-limited or out of quota, the judge leaves controls as they were, with a reason (for example "budget used up" or "unavailable"). Legacy lines are marked **AI unavailable**, a separate status from LOW confidence. The scan still completes.

## Key rotation

Keys are tried in order: `GROQ_API_KEY`, then `GROQ_API_KEY_1` .. `_4`.

| Error | Behaviour |
|-------|-----------|
| 429 rate limit | try next key |
| 401 / 403 / 404 (key rejected, no model access) | try next key |
| 429 daily quota on every key | report `quota_exhausted`, stop calling for this scan |
| 400, timeout, network error | fail this request (interpreter retries / splits) without trying other keys |

Keys that belong to the same Groq organization share one daily quota, so adding keys from the same account does not increase capacity. Key material is never logged.

## Remediation: Deterministic Recipes, and Candidates for Unconfirmed Vendors

**AI does not decide or apply remediation.** Fixes come from deterministic recipes keyed by control and confirmed vendor (`backend/app/remediation/recipes.py`), filled only with validated operator inputs, and are reported fixed only after a full rescan (`backend/app/remediation/engine.py`). AI_VERIFIED proposals and heuristic verdicts never trigger remediation.

For an **unconfirmed** vendor the AI may propose *candidate* command text on request (section 3). A candidate is
validated and simulated deterministically, confirmed by a human, and never executed -it is a proposal for a person,
not a fix the system applies. See [api.md](api.md#remediation).

## Fallback Behavior

Without an API key, or when Groq is unavailable:
* Detection, scoring and deterministic remediation still work.
* Finding explanations and summaries fall back to static text.
* Unknown-vendor controls keep their recognizer, learned-mapping and heuristic results; confirmed learned mappings still apply.
