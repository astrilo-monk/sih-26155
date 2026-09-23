# NetAuditAI Project Overview

NetAuditAI audits network device configurations against 15 security controls, with cited evidence, honest
UNKNOWN / NOT_CONFIGURED results, posture and coverage, framework views, human-confirmed recognizers for unfamiliar
vendors, and deterministic remediation verified by rescan. Built for Smart India Hackathon 2026, problem SIH26155.

Start with the [README](../README.md) (what is supported, setup, limitations) and
[architecture.md](architecture.md) (how it works).

## Repository structure

```text
backend/
  app/
    main.py, config.py        FastAPI app, settings
    api/routes/               scan, remediation, assistant, adaptive (review & recognizers), report
    api/schemas.py            request / response models
    parsers/                  detector + grammar coverage, Cisco IOS and FortiGate parsers
    structure/tokenizer.py    generic statement tokenizer (unknown vendors)
    facts/                    predicates, parser facts, defaults, lexicon, heuristics, recognizers
    controls/                 catalog, judges, evaluator, finding view, framework views
    analysis/                 engine (results → findings), scoring (posture, coverage; legacy score)
    ai/                       Groq client, redaction, AI judge, prompts
    adaptive/                 line capture, relevance, matcher, legacy interpreter / mapper, service
    db/                       SQLite / Postgres migrations, mapping / recognizer repository
    reporting/                per-device PDF compliance report
    remediation/              recipes and verifying engine (templates/ is an empty legacy package)
    models/                   NormalizedConfig, findings, results, field catalog
  tests/                      pytest suite, fixtures, Phase 0 snapshots
frontend/src/
  App.jsx, home/Home.jsx      landing page and hash routing
  app/AppShell.jsx            sidebar navigation, scan loading, shared drawer
  app/                        Upload, Results (Overview), Devices, Checks (Findings), Fix (Remediation),
                              Teach and Learned (Adaptive learning, with LearningFlow), Frameworks,
                              History, FindingDrawer, LegacyInterpretations
  lib/domain.js               the one backend-state → user-facing-state mapping (states, counts, next step)
  lib/useAudit.js             scan-scoped remediation plan, review queue and the inputs a download may use
  api/client.js               API client
  components/ui/primitives.jsx  the shared vocabulary every screen composes: SeverityMeter,
                              StatusLabel, Notice, CodeBlock, Disclosure, DataRow, Tabs, ActionBar
  components/ui/              drawer, evidence, diff and count primitives
  styles/, index.css          design tokens and the screen stylesheets (hand-written CSS,
                              no Tailwind, no CSS-in-JS, no component library)
  utils/                      history (summaries only), form validation
sample/                       Cisco, FortiGate, unknown-vendor, Palo Alto, Juniper and Arista sample configs
docs/                         documentation
```

## API

`/api/scan`, `/api/scan/{id}`, `/api/collect` (+ `/api/collect/capabilities`), `/api/remediate`,
`/api/remediation/plan`, `/api/download-fixed`, `/api/assistant/*`, `/api/adaptive/*`, `/api/report`. Every `/api` route requires an `X-API-Key` header when
`API_KEY` is set. See [api.md](api.md).

## Frontend workflow

A fixed sidebar carrying the assistant panel (ask about the open scan; answers come from its redacted
results). **New scan** (upload, or collect from live devices over SSH) → **Overview** (posture, coverage, critical not assessed, what to do now,
problems with evidence, PDF report) → **Devices** → **Findings** (every check; a drawer with evidence and, with AI
on, *Explain this*) → **Remediation** (fix automatically, needs your input, manual action, cannot safely fix;
verified download; candidate fixes for unconfirmed vendors). Under *Intelligence*: **Adaptive learning**
(this scan's unknown syntax as plain-language questions; drafts, gates and replay under Advanced details; with no
scan open, the learned mappings, shipped and taught) → **Frameworks** → **History** (browser summaries).
