# Key Decisions

The major technical and design decisions, and why.

## 1. Dedicated parsers for Cisco IOS and FortiGate only
Cisco IOS covers routing and switching, FortiGate covers edge firewalls, and both are well documented. Other vendors
use the generic path instead of more parsers: a parser per vendor does not scale, and a half-finished parser would
look more trustworthy than it is.

## 2. Tech stack: FastAPI + React + SQLite (or Postgres) + Groq
- **Python / FastAPI** -fast to build, strong text processing.
- **React / Vite** -a dashboard quickly.
- **SQLite** -administrator knowledge (recognizers, learned mappings, rejected lines) and the AI judge cache must
  survive restarts; SQLite needs no extra service. On a host whose disk is wiped on restart (e.g. Render's free
  tier), `DATABASE_URL` points the same tables at Postgres (e.g. Supabase); the SQL is written once for both and
  tests always use SQLite. Scan results stay in memory: persisting uploaded configurations is not needed for the
  demo and would store secrets.
- **Groq** (`openai/gpt-oss-120b`) -strict JSON-schema output and a free tier. All calls are isolated in
  `backend/app/ai/client.py`.

## 3. Controls over rules, facts over vendor structures
Controls are the security questions; facts are cited statements that answer them. Every control runs on every
configuration, and the vendor only selects where facts come from. The old vendor-gated rules were removed after a
shadow comparison showed identical results on 42 configurations (plan Phase 4).

## 4. Honest statuses and assurance
UNKNOWN and NOT_CONFIGURED exist so missing data is never silently a PASS or a FAIL. Every decision carries an
assurance level; only parser, confirmed and default evidence is decisive.

## 5. Posture and coverage instead of a penalty score
`100 − penalties` scored unassessed checks as passed. Posture measures how secure the decided controls are;
coverage measures how much could be decided. Both are shown, with the range if undecided controls failed or passed,
and critical controls not assessed are listed. The penalty `score` is deprecated.

## 6. AI proposes, deterministic code verifies, humans confirm
AI is used for explanations and for judging undecided controls of unknown vendors. Every AI citation is verified
deterministically; a verified answer is still provisional until an administrator confirms it as a recognizer.
AI never decides compliance, selects a vendor, saves a recognizer or writes remediation.

## 7. Learning = confirmed recognizers, not model training
The system does not retrain or fine-tune a model. It "learns" a dialect only when an administrator confirms a
recognizer, which is stored in SQLite and applied decisively on later scans without AI.

## 8. Deterministic, verified remediation
An invented command can take down network equipment. Fixes are fixed recipes filled with validated operator inputs,
limited to decisive FAILs on confirmed vendors, and only called fixed after the output is rescanned: vendor still
confirmed, coverage not reduced, control passing, nothing regressed. Unsafe cases go to a human.

## 9. Framework views without inventing mappings
Framework views regroup existing results under NIST SP 800-53 Rev. 5, verified CIS items, the DISA Network Device
Management SRG and ISO/IEC 27001:2022 Annex A. Unverified mappings (PCI DSS, CIS Controls v8) were not added,
because they would inflate apparent compliance coverage. ISO Annex A controls are organisational, so a device
result is reported as evidence towards a control, not as the control being met.

## 10. What we deliberately did not build
Ontologies or graph databases, SMT solvers, embeddings or vector databases, local LLMs or fine-tuning, extra vendor
parsers, AI-generated remediation, and large framework crosswalks.
