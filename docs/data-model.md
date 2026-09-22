# Data Model

The main objects, from parsed configuration to API response.

## `NormalizedConfig` -`app/models/normalized.py`
Parser-internal model of a configuration: device (vendor, hostname, OS version), interfaces, management access (VTY,
console, SSH/HTTP/Telnet), authentication, SNMP, logging, NTP, ACLs, firewall policies, VPN proposals, banners,
services, plus `raw_config` / `raw_lines` and the source line numbers of every parsed object. For unknown vendors it
only carries the raw lines, captured lines and adaptive records; controls never read it directly.

## `SecurityFact` -`app/facts/predicates.py`
```python
predicate: str        # one of 16 predicates, each consumed by a control
value: Any            # concrete value | None (undetermined) | NOT_SET (parser-read absence)
assurance: Assurance  # parser | confirmed | default | heuristic | ai_verified
evidence: Evidence    # cited line numbers and text
subject, scope, unit, provenance
control_id            # set on AI judge facts: only that control may read them
```

## `Control` and `Mapping` -`app/controls/catalog.py`
A control has `control_id`, `title`, `question`, `kind`, `severity`, `category`, `needs` (predicates),
`remediation_keys` and `mappings`. A `Mapping` has `framework`, exact `version`, `requirement_id`, `title` and an
optional `vendor` (product benchmarks such as CIS).

## `ControlResult` -`app/models/results.py`
```python
control_id, status          # pass | fail | not_configured | unknown | n_a
assurance                   # set on decided results (and ai_verified on AI proposals)
proposed_status             # the AI's verdict awaiting confirmation
scope, reason, evidence, facts
failure: FailureDetail      # severity, description, impact, recommendation -present exactly when FAIL
```
A `Finding` (`app/models/findings.py`) is the view of a FAIL result used by the findings table.

## `LearnedMapping` -`app/db/mappings.py`
Row of SQLite `learned_mappings`. A **recognizer** has `extraction_method = "recognizer"`, `command_pattern`
(typed-slot template), `predicate`, `subject`, `scope_template`, `dialect_fingerprint`, `negatives`,
`constant_value` (JSON value or enum table), `example_line`, `confirmed`, `active`, and `source`
(`seed` = shipped knowledge from `backend/data/seed_recognizers.json`, `runtime` = taught on this deployment). Learned field mappings (legacy
review queue) use `normalized_field` instead of a predicate.

## Remediation -`app/remediation/engine.py`
`Outcome`: `control_id`, `status` (`fixed`, `needs_input`, `manual_review`, `verification_failed`, `no_recipe`,
`vendor_unverified`, `provisional`, `not_failing`), `reason`, `explanation`, `warnings`, `scopes`, `evidence`,
`inputs` / `missing_inputs`, `diff`, `checks`, `before` / `after` summaries, `fixed_config`. `Plan` holds the
outcomes of every failing control of one configuration and the combined verified output.

## `Candidate` -`app/remediation/candidates.py`
A proposed remediation for one control of one configuration whose vendor is **not** confirmed:
`config_index`, `control_id`, `source` (`derived` -worked out from the configuration itself | `manual` | `ai`),
`command` (text, never executed), `explanation`,
`confidence`, `assumptions`, `status` (`draft` | `verified` | `unverified` | `rejected` | `confirmed`), `reason`,
the cited `evidence`, `control_status_before` / `_after`, `checks` (`target`, `no_regression`, `generic_path`),
the simulated `diff`, `created_at` and `confirmed_at`, and -only while `verified` (or `confirmed` after
verifying) -`verified_config`: the edited **copy** the candidate was verified against, byte-for-byte the text the
generic engine re-analysed. Any other status clears it. Candidates live in the scan's in-memory entry
(`_scan_store[scan_id]["candidates"]`) for that scan only: they are never persisted, never applied to the stored
configuration, and never part of the confirmed-vendor `/download-fixed` output. `verified_config` leaves the
backend only through `POST /api/remediation/candidate/download`, as a *verified corrected copy of the uploaded
configuration* -the API schema exposes a `download_available` flag, never the text.

## Scan response -`ScanResultResponse` in `app/api/schemas.py`
`scan_id`, `devices`, `vendor_identification[]`, `results[]` (every control × config), `findings[]`, `posture`,
`coverage`, `posture_bounds`, `critical_unassessed`, `assessed_count` / `unresolved_count` (applicable controls
decided from decisive evidence, and the ones left undecided), `unreadable_configs[]` (uploads holding no security
configuration at all -reported, never scored), `frameworks[]`, `adaptive` / `adaptive_configs[]` (AI calls,
cache hits, provisional reasons, vendor evidence), severity counts and the deprecated `score`.

## Resolution queue -`UnresolvedQueueResponse` in `app/api/schemas.py`
The undecided side of coverage, built from the same `control_outcomes`: `assessed_count`, `unresolved_count` and
`items[]`, each with the control, its `status` (`unknown` | `not_configured`), why it could not be decided, the
evidence it did cite, the `needs` predicates, `suggested_lines[]` (lines of this configuration that mention the
setting, with a heuristic's reading where there is one) and `action` (`teach`, or `blocked` with a reason).
Listing a control never changes it. `app/facts/teaching.py` turns an administrator's answer about one line into the
asserted candidate `draft_recognizer` validates -the same recognizer and the same gates as any other.

## Report document model -`app/reporting/report.py`
The per-device compliance report as a list of blocks (`h1`/`h2`/`h3`/`p`/`note`, `table`, `mono`), rendered to PDF
by `render_pdf`. Built from the redacted `ScanResultResponse` plus the remediation plan; nothing is evaluated there.
