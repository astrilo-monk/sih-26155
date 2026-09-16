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
    api/routes/               scan, remediation, assistant, adaptive (review & recognizers)
    api/schemas.py            request / response models
    parsers/                  detector + grammar coverage, Cisco IOS and FortiGate parsers
    structure/tokenizer.py    generic statement tokenizer (unknown vendors)
    facts/                    predicates, parser facts, defaults, lexicon, heuristics, recognizers
    controls/                 catalog, judges, evaluator, finding view, framework views
    analysis/                 engine (results → findings), scoring (posture, coverage; legacy score)
    ai/                       Groq client, redaction, AI judge, prompts
    adaptive/                 line capture, relevance, matcher, legacy interpreter / mapper, service
    db/                       SQLite migrations, mapping / recognizer repository
    remediation/              recipes and verifying engine (templates/ is an empty legacy package)
    models/                   NormalizedConfig, findings, results, field catalog
  tests/                      pytest suite, fixtures, Phase 0 snapshots
frontend/src/
  App.jsx, api/client.js      workflow and API client
  components/                 overview, analysis path, findings, frameworks, remediation, review & recognizers, history
  utils/                      history (summaries only), form validation
sample/                       Cisco, FortiGate, unknown-vendor and Palo Alto sample configs
docs/                         documentation
plan.md                       phase-by-phase implementation record
```

## API

`/api/scan`, `/api/scan/{id}`, `/api/remediate`, `/api/remediation/plan`, `/api/download-fixed`,
`/api/assistant/*`, `/api/adaptive/*`. See [api.md](api.md).

## Frontend workflow

Scan (upload) → **Results** overview (posture, coverage, critical not assessed, what to do now, problems with
evidence) → **Fix** (fix automatically, needs your input, manual action, cannot safely fix; verified download) →
**Teach** (plain-language questions about unfamiliar lines; drafts, gates and replay under Advanced details) →
**All checks**, **Devices**, **Frameworks** → **Learned** (stored recognizers; legacy review queue) →
**History** (browser summaries).
