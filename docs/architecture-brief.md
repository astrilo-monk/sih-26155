# NetAuditAI — Architecture (2-page brief)

SIH 2026 · Problem Statement 26155 · AI-Driven Multi-Vendor Network Security Compliance Auditor.
The full design is in [architecture.md](architecture.md); this brief is the evaluation deliverable.

## 1. The idea in one paragraph

NetAuditAI does not try to parse every vendor. It asks **15 security questions** (controls: Telnet enabled? SSH
version? idle timeout? remote syslog? permissive rule? …) and extracts only the **security facts** those questions
need. A fact is one cited, typed statement — "Telnet reachable = true, line 31, confirmed". Controls read facts,
never vendor syntax, so every control runs on every configuration, whatever produced the facts: a vendor parser,
a recognizer an administrator taught, shipped seed knowledge, a lexicon heuristic, or the AI. Each fact carries its
**assurance**, and only decisive facts are scored; everything else is shown as provisional.

## 2. Pipeline

```text
Upload (single or bulk, CLI text or JSON export)
  → Ingest: UTF-8, ≤ 2 MB, JSON flattened to one statement per object, secrets redacted before any AI call
  → Vendor identification: fingerprint + parse coverage   (a look-alike is never "confirmed")
  → Confirmed vendor ─→ dedicated parser (Cisco IOS, FortiGate) ──────────────────────┐
  → Anything else   ─→ generic tokenizer (blocks, indentation, set-style, /menu paths)  │
                        → recognizers (taught + 97 shipped)  → lexicon heuristics      │
                        → AI judge for what is still undecided (budgeted, cited)       │
  → Security facts (value, evidence lines, assurance) ←────────────────────────────────┘
  → Control evaluation: PASS / FAIL / UNKNOWN / NOT_CONFIGURED / N/A per control
  → Posture (pass ÷ decided) + Coverage (decided ÷ applicable) + critical controls not assessed
  → Framework views: NIST SP 800-53 Rev. 5 · CIS · DISA NDM SRG · ISO/IEC 27001:2022 Annex A
  → Remediation: vendor CLI for confirmed vendors, verified by re-parse; candidate fixes simulated on a copy
  → Per-device PDF report (ReportLab)
```

## 3. Normalization — the vendor-neutral model

The schema is the fact vocabulary (`app/facts/predicates.py`): 16 predicates such as
`mgmt.remote_access.protocol_enabled[telnet]`, `mgmt.ssh.version`, `mgmt.session.idle_timeout` (minutes),
`auth.password.storage`, `log.remote.destination`, `boundary.policy.permit_any`. A Cisco `transport input telnet`,
a Junos `services { telnet; }`, an EXOS `enable telnet` and a Gaia `set telnet-server enabled true` all become the
same fact. Structured exports (AWS security groups, Azure NSGs, SONiC `config_db.json`) are flattened so a rule
object reads as one statement: `SecurityGroups IpPermissions FromPort 22 IpProtocol tcp CidrIp 0.0.0.0/0 ToPort 22`.

## 4. Dynamic adaptation — the training loop

1. An unfamiliar configuration is scanned. Lines the engine could not decide appear in the **Adaptive learning**
   view, each with the control it could answer.
2. The administrator picks a line and states its meaning in plain words ("this sets the idle timeout"). No regex,
   no code: the system drafts a **recognizer** — a typed template such as `idle-timeout {duration:min}` scoped to
   its block, with `{neg}` so one entry reads both `telnet server` and `no telnet server`.
3. Safety gates (`validate_recognizer`) refuse templates that could match anything: two keywords, stated polarity
   or a value table, a unit for durations, the line must name the setting, and **no secret is ever stored**.
4. The recognizer is saved in SQLite or Postgres (Supabase) and applies to the next scan immediately — decisive,
   deterministic, no AI call, **no redeployment**. It can be stopped or edited from the Knowledge page.

Shipped seed knowledge is the same mechanism, reviewed in Git: 97 recognizers covering Juniper Junos, Palo Alto
PAN-OS, Arista EOS, Huawei VRP, HPE Aruba AOS-CX, Check Point Gaia, Extreme EXOS, MikroTik RouterOS and AWS
security groups, so a fresh deployment already reads these dialects before anyone teaches it.

## 5. Where AI is used — and where it is not

| Step | AI? | Why |
|---|---|---|
| Deciding compliance | **Never** | Controls are deterministic Python; results are reproducible and auditable |
| Reading an unknown dialect | Optional escalation | The AI judge sees only redacted scopes of undecided controls, must cite lines, and every citation is re-verified; its answer is a *proposal*, never scored until a human confirms it |
| Explaining a finding | Optional | "Explain this" in the finding drawer, redacted evidence only |
| Candidate remediation | Optional | Proposed commands are simulated on a copy and re-evaluated before a human confirms |

Secret redaction (`app/ai/redaction.py`) runs before every AI call and every response that quotes configuration:
passwords, hashes, PSKs and SNMP communities become typed placeholders (`<SECRET:type7>`), so a weak-encoding
control still knows the password is Type 7 without the value ever leaving the process.

## 6. Multi-framework compliance

Each control maps to versioned requirements: NIST SP 800-53 Rev. 5 (e.g. AC-17, IA-5, AU-4), CIS Benchmarks for the
confirmed vendors, DISA Network Device Management SRG, and ISO/IEC 27001:2022 Annex A (A.8.5, A.8.20 …). The
Frameworks view regroups the same results per framework, so one scan answers all four.

## 7. Report

One PDF per device (a zip for several): device identification (hostname, vendor, OS version, hardware model and
serial number when the uploaded text states them), posture with coverage beside it, PASS/FAIL per control with
severity and evidence lines, framework mapping, device-specific remediation CLI with its verification, and the list
of undecided controls with what each needs. The report states only what the scan decided and never prints a secret.

## 8. Technology

Python 3.10 · FastAPI · ReportLab · SQLite or Postgres (psycopg) · Groq LLM API (optional) · React 19 + Vite.
Tests: 1170 backend (pytest) and 82 frontend (Vitest). Everything runs without AI; AI only raises coverage.

## 9. Extending it without code changes

| New… | How |
|---|---|
| Vendor or OS version | Teach its lines once in the UI, or add seed entries (JSON) — no parser, no redeploy |
| Structured format | Flattened automatically; its rule lines are taught like any CLI line |
| Framework | Add a mapping to the control catalog (`app/controls/catalog.py`) |
| Security question | Add a predicate, a control and a judge; every configuration gets it |
