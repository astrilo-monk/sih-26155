# Glossary

Terms used in the code, the API and the UI, in alphabetical order. Each entry names where the concept lives.

| Term | Meaning | Where |
|---|---|---|
| **Absence** | A setting no line states. On a confirmed parser it is `NOT_SET`; on the generic path it is NOT_CONFIGURED unless *learned absence* applies. Never a PASS. | `facts/predicates.py` |
| **Any-to-any rule** | An ACL entry or firewall policy that permits any source to any destination for any service (BOUNDARY-001). | `controls/judges.py: permit_any` |
| **Assurance** | How trustworthy a fact is: `parser`, `confirmed`, `default` (decisive) or `heuristic`, `ai_verified` (provisional). A verdict takes the weakest assurance it cites. | `models/results.py` |
| **Attack path** | A chain of decided FAILs that together describe how an attacker gets in, with the fix that breaks it. Four chains exist. | `analysis/attack_paths.py` |
| **Block path / scope path** | The enclosing blocks of a line (`system > services`), worked out from braces, keyword blocks and indentation without vendor knowledge. | `adaptive/context.py`, `structure/tokenizer.py` |
| **Candidate** | A proposed command for an unconfirmed vendor (derived, typed or AI-drafted). Simulated on a copy, confirmed by a person, never executed. | `remediation/candidates.py` |
| **Confirmed (vendor)** | The detector matched the vendor and the file follows its grammar. Selects the parser, defaults, recipes and CIS view. | `parsers/detector.py` |
| **Confirmed (assurance)** | A fact read by a recognizer (seed or taught) or a learned mapping. Decisive. | `facts/recognizers.py` |
| **Control / check** | One of 23 security questions (MGMT-001 … CRYPTO-002). Runs on every configuration. | `controls/catalog.py` |
| **Control kind** | `prohibition` (must be off), `requirement` (must exist), `threshold` (within a limit), `relational` (depends on how objects relate). | `controls/catalog.py` |
| **Coverage** | Weighted share of applicable checks decided from decisive evidence. | `analysis/scoring.py` |
| **Critical not assessed** | Critical checks that were not decided; listed next to posture. | `analysis/scoring.py` |
| **Decisive** | Evidence that may move a score: `parser`, `confirmed`, `default`. | `models/results.py: DECISIVE_ASSURANCE` |
| **Default (assurance)** | A documented vendor default for a confirmed vendor, used only when the file is silent. | `facts/defaults.py` |
| **Derived candidate** | A candidate NetAuditAI works out itself by removing the cited lines; only for prohibitions and relational checks. | `candidates.derive` |
| **Dialect** | A configuration language (Junos, PAN-OS, RouterOS …). On the generic path the dialect is inferred from which seeds matched, never from a vendor name. | `facts/recognizers.py: _dialect` |
| **Drift** | Changes since the last audit of the same device: fixed, new, no longer decided. | `analysis/drift.py` |
| **Evidence** | The cited line numbers and text behind a fact or verdict. | `models/results.py: Evidence` |
| **Fact / SecurityFact** | One cited, typed statement a check needs: predicate, value, assurance, evidence, scope. | `facts/predicates.py` |
| **Fence** | The `BEGIN CONFIG <tag>` … `END CONFIG <tag>` wrapper that marks configuration text in a prompt as data. | `ai/fence.py` |
| **Fleet check** | A problem visible only across devices (shared SNMP community, NTP or syslog mismatch). | `analysis/fleet_checks.py` |
| **Generic path** | How every configuration without a confirmed parser is read: flatten, tokenize, recognizers, heuristics, optional AI. | `structure/`, `facts/` |
| **Grammar coverage** | The share of meaningful lines that follow the detected vendor's grammar. Below 0.7 (with 3+ foreign lines) the vendor is unverified. | `parsers/coverage.py` |
| **Heuristic** | A provisional reading of an unfamiliar line through the synonym lexicon. Shown as "Suspected", never scored. | `facts/heuristics.py`, `facts/lexicon.py` |
| **Judge** | The function that says what one fact means for one control (PASS / FAIL / UNKNOWN). | `controls/judges.py` |
| **AI judge** | The optional AI escalation for undecided checks of unknown vendors. Its output is verified and stays provisional. | `ai/judge.py` |
| **Learned absence** | A FAIL from absence on the generic path, allowed only for 5 settings no device ships with, when the dialect is understood and knows how it writes them. | `facts/recognizers.py: _absence` |
| **Learned mapping** | A legacy administrator-confirmed mapping from a line to a normalized field (review queue). | `db/mappings.py` |
| **Ledger** | The append-only, hash-chained record of scans, recognizers, candidate decisions and reports. | `app/ledger.py` |
| **Look-alike** | A configuration that resembles Cisco IOS or FortiOS but is another platform (NX-OS, ASA, FortiSwitch …). Reported unverified. | `tests/fixtures/lookalikes/` |
| **N_A** | The check cannot apply: an optional feature a confirmed parser found none of, or a platform profile (cloud formats). | `controls/evaluate.py` |
| **NormalizedConfig** | The parsers' internal model. Controls never read it directly. | `models/normalized.py` |
| **NOT_CONFIGURED** | Nothing relevant was found. Never counted as PASS; counted as undecided. | `models/results.py` |
| **NOT_SET** | A fact value meaning "read as absent" (by a confirmed parser or learned absence). | `facts/predicates.py` |
| **Organisation policy** | A JSON file that tightens thresholds and names approved servers. Can only tighten. | `controls/policy.py` |
| **Platform profile** | A rule that marks device-only checks N/A for formats that cannot have them (security groups, Terraform, NSG, GCP firewall). | `data/platform_profiles.json` |
| **Posture** | Weighted decided PASS ÷ weighted decided (PASS + FAIL) × 100. "-" when nothing is decided. | `analysis/scoring.py` |
| **Posture bounds** | Posture if every undecided check failed … if every undecided check passed. | `analysis/scoring.py` |
| **Predicate** | The name of a fact (`mgmt.ssh.version`). 23 exist; each is read by at least one check. | `facts/predicates.py` |
| **Proposed status** | The AI's PASS / FAIL awaiting confirmation; the status itself stays UNKNOWN. | `ControlResult.proposed_status` |
| **Provisional** | A verdict whose weakest evidence is `heuristic` or `ai_verified`. Shown, never scored. | |
| **Recipe** | A deterministic fix for one check on one confirmed vendor (41 exist). | `remediation/recipes.py` |
| **Recognizer** | A typed-slot template (`set system services telnet`, `idle-timeout {duration:min}`) that reads one concept in one dialect and yields a decisive fact. Shipped as a seed or taught by an administrator. | `facts/recognizers.py` |
| **Redaction** | Replacing secret values with typed placeholders (`<SECRET:type7>`) before any AI call, response, report or archive. | `ai/redaction.py` |
| **Resolution queue** | The list of every applicable check coverage left out, with suggested lines to teach. | `GET …/unresolved` |
| **Risk** | 0 to 100 per device: worst decided problem + exposure + attack paths, times asset criticality. | `analysis/risk.py` |
| **Scope** | The object a fact or FAIL is about (an interface, a VTY range, a policy). One FAIL per failing scope. | `SecurityFact.scope` |
| **Security Baseline Model** | The vendor-neutral export of one configuration's facts (`GET /api/scan/{id}/baseline`). | `routes/scan.py` |
| **Seed** | A recognizer shipped in `data/seed_recognizers.json` (`source = seed`), reviewed like code. | `facts/seed.py` |
| **Seed write-back** | A fix for an unconfirmed vendor where the recognizer that read the failing line writes its secure value. | `remediation/writeback.py` |
| **Slot** | A typed hole in a recognizer template: `{int}`, `{host}`, `{ip}`, `{duration}`, `{enum:name}`, `{polarity}`, `{neg}`, `{any}`, `{rest}`, `{community:RO}`. | `adaptive/matcher.py` |
| **UNKNOWN** | Something relevant exists but could not be decided. Counted as undecided. | `models/results.py` |
| **Unverified (vendor)** | Looks like Cisco IOS or FortiGate but does not follow its grammar. Takes the generic path with vendor `unknown`. | `parsers/detector.py` |
| **Verified candidate** | A candidate whose simulation on a copy showed the check no longer FAILs and nothing regressed. A claim about the file, not about the device. | `remediation/candidates.py` |
