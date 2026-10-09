# Key Decisions

The major technical and design decisions, why each was made, and what it costs. Each entry is a short decision record:
**context** (the pressure), **decision**, **consequences** (good and bad).

| # | Decision | Status |
|---|---|---|
| 1 | [Dedicated parsers for Cisco IOS and FortiGate only](#1-dedicated-parsers-for-cisco-ios-and-fortigate-only) | in force |
| 2 | [Confirm a vendor by grammar coverage, not by fingerprint](#2-confirm-a-vendor-by-grammar-coverage-not-by-fingerprint) | in force |
| 3 | [Controls over rules, facts over vendor structures](#3-controls-over-rules-facts-over-vendor-structures) | in force |
| 4 | [Honest statuses and assurance](#4-honest-statuses-and-assurance) | in force |
| 5 | [Posture and coverage instead of a penalty score](#5-posture-and-coverage-instead-of-a-penalty-score) | in force; old `score` deprecated |
| 6 | [AI proposes, deterministic code verifies, humans confirm](#6-ai-proposes-deterministic-code-verifies-humans-confirm) | in force |
| 7 | [Learning means confirmed recognizers, not model training](#7-learning-means-confirmed-recognizers-not-model-training) | in force |
| 8 | [Ship reviewed seed knowledge](#8-ship-reviewed-seed-knowledge) | in force |
| 9 | [Deterministic, verified remediation; candidates for the rest](#9-deterministic-verified-remediation-candidates-for-the-rest) | in force |
| 10 | [Framework views without inventing mappings](#10-framework-views-without-inventing-mappings) | in force |
| 11 | [Never store the configuration](#11-never-store-the-configuration) | in force |
| 12 | [Live collection on by default, fenced](#12-live-collection-on-by-default-fenced) | in force |
| 13 | [Offline AI through any OpenAI-compatible server](#13-offline-ai-through-any-openai-compatible-server) | in force |
| 14 | [A hash-chained ledger in the same database](#14-a-hash-chained-ledger-in-the-same-database) | in force |
| 15 | [Tech stack](#15-tech-stack) | in force |
| 16 | [What we deliberately did not build](#16-what-we-deliberately-did-not-build) | in force |

---

## 1. Dedicated parsers for Cisco IOS and FortiGate only

**Context.** The problem statement names the trap: a hard-coded command library "becomes obsolete as vendors release
firmware updates". A parser per vendor is a race that cannot be won, and a half-finished parser reads every setting
it does not understand as *absent*, which turns into confident PASS or FAIL verdicts.

**Decision.** Two parsers: Cisco IOS / IOS-XE (routing and switching) and FortiGate (edge firewalls), both well
documented. Every other vendor uses the generic path (tokenizer, recognizers, heuristics, optional AI).

**Consequences.** Two vendors get decisive verdicts, recipes and CIS views from day one. Everything else starts
provisional and becomes decisive through shipped or taught recognizers. Nobody can claim "dedicated support" for
Palo Alto or Juniper, and the docs never do.

## 2. Confirm a vendor by grammar coverage, not by fingerprint

**Context.** Arista EOS, NX-OS, IOS-XR and Dell OS10 all look like IOS to a fingerprint (`hostname`, `!`,
`interface`). Reading them with the IOS parser would mark everything it cannot see as missing.

**Decision.** A vendor is **confirmed** only when the file follows its grammar: no profile mismatch, no run of 5
foreign statements, coverage at least 0.7. Otherwise it is **unverified** and takes the generic path.

**Consequences.** Look-alikes are never misread (pinned by fixtures in `tests/fixtures/lookalikes/`). The cost: an
unusual but genuine IOS file can come out unverified until its command root is added to the grammar.

## 3. Controls over rules, facts over vendor structures

**Context.** Vendor-gated rules ("if Cisco, check X") duplicate every question per vendor and silently skip vendors
nobody wrote rules for.

**Decision.** Controls are the security questions; facts are cited statements that answer them. Every control runs on
every configuration, and the vendor only decides where facts come from. The old vendor-gated rules were removed after
a shadow comparison showed identical results on 42 configurations.

**Consequences.** A new vendor needs facts, not new checks. A new question needs one predicate, one control and one
judge, and immediately runs on every vendor.

## 4. Honest statuses and assurance

**Context.** In an audit, "I could not determine this" is worth more than a confident wrong answer.

**Decision.** UNKNOWN and NOT_CONFIGURED exist so missing data is never silently a PASS or a FAIL. Every fact carries
an assurance; only `parser`, `confirmed` and `default` are decisive; a verdict takes the weakest assurance it cites.

**Consequences.** Coverage can be low on an unfamiliar dialect, and the UI says so instead of hiding it. The
resolution queue turns every undecided check into something an administrator can resolve.

## 5. Posture and coverage instead of a penalty score

**Context.** `100 − penalties` scored every unassessed check as passed: an unreadable file scored 100.

**Decision.** Posture measures how secure the decided checks are; coverage measures how much could be decided. Both
are shown, with the range if undecided checks failed or passed, and critical checks not assessed are listed.

**Consequences.** A file with nothing decided shows posture "-" and coverage 0. The old `score` is still returned,
deprecated, for existing scripts.

## 6. AI proposes, deterministic code verifies, humans confirm

**Context.** An LLM reading configurations is useful for unfamiliar syntax and dangerous everywhere else: it can be
prompt-injected by a banner, it is not reproducible, and it cannot be audited.

**Decision.** AI is used for explanations, chat, judging undecided checks of unknown vendors, and drafting candidate
commands on request. Every AI citation is verified deterministically; a verified answer stays provisional until an
administrator confirms it as a recognizer. AI never decides compliance, selects a vendor, saves a recognizer or
writes a recipe.

**Consequences.** Verdicts are reproducible with AI on or off. 0 of 6 live prompt-injection attacks succeeded, and a
fully hijacked model is tested to change nothing. The cost: AI raises coverage only after a person confirms.

## 7. Learning means confirmed recognizers, not model training

**Context.** "AI-powered training" in the problem statement could mean fine-tuning. A fine-tuned model is opaque,
slow to update and cannot be rolled back line by line.

**Decision.** The system "learns" a dialect only when an administrator confirms a recognizer: a typed-slot template
that passes safety gates, stored in the knowledge store and applied decisively on later scans without AI.

**Consequences.** Learning is instant (the very next scan), auditable (every recognizer is a row with its example
line, in the ledger), reversible (stop it) and needs no redeployment.

## 8. Ship reviewed seed knowledge

**Context.** A fresh deployment that knows no dialect gives a poor first impression and makes every user teach the
same Junos lines.

**Decision.** Ship 396 recognizers for 16 dialects and the cloud formats in `backend/data/seed_recognizers.json`,
reviewed like code, loaded into an empty database on first start, marked `source=seed`.

**Consequences.** PAN-OS, Junos, Huawei and others answer several checks before anyone teaches anything. A wrong seed
is a real defect, so the file is treated as production code and every entry passes the same gates as a taught one.

## 9. Deterministic, verified remediation; candidates for the rest

**Context.** An invented command can take down network equipment.

**Decision.** For confirmed vendors: fixed recipes filled with validated operator inputs, only for decisive FAILs,
only called fixed after a rescan proves the vendor is still confirmed, coverage did not drop, the check passes and
nothing regressed. For unconfirmed vendors: seed write-back (the recognizer that read the line writes its secure
value), and otherwise **candidates** (derived from the file, typed, or AI-drafted) that are simulated on a copy and
confirmed by a person. Nothing is ever executed on a device.

**Consequences.** Every "fixed" is proven against the file. A verified candidate only claims the finding is gone from
this file, never that the command is safe to run, and the UI says so.

## 10. Framework views without inventing mappings

**Context.** Large crosswalks inflate apparent compliance and are hard to verify.

**Decision.** Map only what a check actually answers, with exact versions: NIST SP 800-53 Rev. 5, verified CIS items
(Cisco IOS XE 17.x, FortiGate 7.4.x), the DISA Network Device Management SRG and ISO/IEC 27001:2022 Annex A. PCI DSS
and CIS Controls v8 are **not** mapped.

**Consequences.** 24 checks answer 80 requirements. ISO Annex A controls are organisational, so a device result is
reported as evidence towards one, never as the control being met.

## 11. Never store the configuration

**Context.** Configurations hold passwords, keys and topology. Persisting them would make the database the most
valuable target in the system.

**Decision.** Uploaded and collected configurations live only in process memory. What survives a restart is the
redacted scan response and plans (`scans` table), so history and PDFs still work.

**Consequences.** After a restart an archived scan is read-only; teaching or fixing it asks for the file again
(`409`). Several uvicorn workers do not share active scans.

## 12. Live collection on by default, fenced

**Context.** The problem statement's suggested workflow pulls configurations from devices. An endpoint that opens SSH
to any host it is given is also a server-side request forgery.

**Decision.** On by default for an operator on their own network, bounded to RFC1918 and loopback, link-local refused
by name, the vetted address handed to the driver, credentials request-scoped, one read-only command.
`LIVE_COLLECTION_ENABLED=false` closes it.

**Consequences.** Works out of the box on a laptop. Any internet-reachable deployment must turn it off; the deployment
checklist says so first.

## 13. Offline AI through any OpenAI-compatible server

**Context.** Air-gapped and government networks (the problem statement is from NTRO) cannot send configuration
excerpts to a cloud API, even redacted.

**Decision.** `LOCAL_AI_URL` routes every AI call to a local OpenAI-compatible server (Ollama, llama.cpp, vLLM).
Redaction and fencing apply unchanged.

**Consequences.** Nothing leaves the network. A smaller local model only affects the optional parts, because no
verdict depends on AI.

## 14. A hash-chained ledger in the same database

**Context.** An auditor needs to show that a report or a taught recognizer was not changed after the fact.

**Decision.** Every archived scan, taught recognizer, candidate decision and report appends a SHA-256-chained entry
holding only content hashes. A report PDF can be verified byte for byte.

**Consequences.** Tampering inside the database is detected. It is not an external anchor: the latest hash must be
kept elsewhere (the PDF prints it) to prove the whole database was not replaced.

## 15. Tech stack

| Choice | Why |
|---|---|
| Python 3.10 + FastAPI | fast to build, strong text processing, typed request models, interactive docs |
| React 19 + Vite, hand-written CSS | a dashboard quickly, no runtime UI dependencies beyond React |
| SQLite, or Postgres via `DATABASE_URL` | knowledge must survive restarts; SQLite needs no service, Postgres for hosts that wipe their disk; the SQL is written once for both and tests always use SQLite |
| Groq (`openai/gpt-oss-120b`) | strict JSON-schema output and a free tier; all calls isolated in `app/ai/client.py` |
| ReportLab | PDF reports without a browser |
| Netmiko (NAPALM optional) | SSH collection across 12 platforms |

## 16. What we deliberately did not build

* **More vendor parsers** (decision 1).
* **Fine-tuning or training a model** (decision 7).
* **AI-decided compliance or AI-written recipes.** AI may draft a *candidate* command for an unconfirmed vendor, which
  is verified and confirmed like a typed one (decision 9), but it never writes a recipe and its text is never
  presented as verified until the simulation passes.
* **Ontologies, graph databases, SMT solvers, embeddings or vector databases.** The questions are bounded (24 checks);
  typed recognizers and deterministic judges answer them without that machinery.
* **Large framework crosswalks** (decision 10).
* **Executing changes on devices.** NetAuditAI reads devices and never writes to one.

Earlier versions of this list said "no local LLMs" and "no AI-generated remediation". Both changed: offline AI was
added for air-gapped sites (decision 13), and AI-drafted *candidates* (never recipes) were added for unconfirmed
vendors (decision 9).
