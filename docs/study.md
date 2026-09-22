# NetAuditAI -Study Guide

A short guide for presenting and defending the project.

## 1. The pitch

Network engineers read thousands of configuration lines from routers and firewalls of different vendors to find
weaknesses. NetAuditAI:

1. **Detects the vendor deterministically** and confirms it by checking that the configuration really follows that
   vendor's grammar.
2. **Extracts security facts** with a dedicated parser (Cisco IOS, FortiGate) or, for any other vendor, a generic
   tokenizer and keyword heuristics.
3. **Answers 15 security controls** with PASS / FAIL / UNKNOWN / NOT_CONFIGURED and the exact lines as evidence.
4. **Reports posture and coverage separately**, so "we could not check it" never looks like "it is secure".
5. **Uses AI only for what stayed undecided**, verifies every AI citation in code, and keeps the answer provisional
   until an administrator confirms it. A confirmation becomes a recognizer reused on every future scan.
6. **Fixes confirmed findings deterministically** and proves each fix by rescanning the result.

## 2. Where things are

| Question | Code |
|---|---|
| How is the vendor detected? | `backend/app/parsers/detector.py`, `coverage.py` |
| How are configs parsed? | `backend/app/parsers/cisco_ios.py`, `fortinet.py`, `backend/app/structure/tokenizer.py` |
| What are the security checks? | `backend/app/controls/catalog.py`, `judges.py`, `evaluate.py` |
| Where do facts come from? | `backend/app/facts/` |
| How is the score computed? | `backend/app/analysis/scoring.py` |
| What does AI do? | `backend/app/ai/judge.py`, `redaction.py` |
| How does it learn? | `backend/app/facts/recognizers.py`, `backend/app/db/` |
| How are fixes made? | `backend/app/remediation/recipes.py`, `engine.py` |
| Framework views? | `backend/app/controls/frameworks.py` |
| UI? | `frontend/src/app/` (pages), `frontend/src/lib/domain.js` (backend state → user-facing state) |

## 3. Likely questions

**Is this "multi-vendor"?** Two vendors have dedicated parsers. Every other vendor gets the same 15 controls through
the generic path, marked provisional until an administrator confirms recognizers. We do not claim parser-level
assurance for them.

**Does AI decide compliance?** No. AI answers only undecided controls of unknown vendors, every citation is checked
against the cited line, and the answer never changes posture, coverage, findings or remediation until a human
confirms it.

**What if AI hallucinates?** A citation that does not exist, is in another scope, or does not state the value is
discarded and never reaches the review queue. AI cannot infer a PASS from something missing.

**Do secrets go to the AI?** The configuration is redacted and every prompt is scrubbed of known secrets first.
Redaction is pattern-based, which we state as a limitation.

**Does it learn automatically?** Only through confirmed recognizers: an administrator confirms a line, the recognizer
is validated, replayed, stored in SQLite and reused after restarts. No model is trained.

**Can a fix break the device?** Fixes are fixed templates, not AI output, and apply only to decisive findings on
confirmed vendors. Each is rescanned: vendor still confirmed, parse coverage not reduced, control passing, nothing
else worse. Risky changes carry warnings, and unsafe ones (weak passwords, AAA lockout, any-any rules) go to a human.

**Is a 100 posture "compliant"?** No. Posture covers decided controls only; coverage says how much was decided, and
the framework view states it is not a certification.
