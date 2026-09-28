# output.md: full test run, 2026-09-28

Everything in `updates.md` is done. This file records the final full test run and three configuration files
scanned through the website, run locally.

## 1. Automated tests

| Suite | Command | Result |
|---|---|---|
| Backend | `cd backend && venv\Scripts\python -m pytest tests -q -n auto` | **1644 passed**, 2 skipped (live AI, need `NETAUDIT_LIVE_AI=1`) |
| Frontend | `cd frontend && npm test` | **151 passed** (29 files) |
| Browser, end to end | `cd frontend && npx playwright test` | **1 passed**: the two-minute demo path over four files, in 30.5 s of machine time |
| Benchmark | `python backend/scripts/benchmark.py` | planted **18/20**, labelled fixtures **89/112**, held-out real configurations **21/21** (first run 20/21); **0 missed, 0 false alarms** in every set |

## 2. Three configuration files on the website

**Setup:**
- Backend: `uvicorn app.main:app --port 8001`, the port the local `frontend/.env` points at.
- Frontend: `npx vite --port 5173`.
- Driven in a real browser (Playwright), one file per scan, through *New scan → Start scan*.
- The local knowledge database was used as it is.
- AI was **available** (Groq, a key configured outside `backend/.env`), so AI could add proposals, but a proposal never changes a decided result.

### 2.1 `backend/tests/fixtures/demo/cisco_edge_vulnerable.cfg`: Cisco IOS-XE, dedicated parser

| | |
|---|---|
| Read as | Cisco IOS, confirmed; the parser understood 100% of lines; AI not used |
| Score (posture) | **12/100** |
| Checks decided (coverage) | **95%** (19 assessed, 1 undecided, 3 N/A) |
| Risk | **CRITICAL 80/100** |
| Problems | **15** (5 critical, 5 high, 5 medium, 0 low): 10 can be fixed automatically, 1 needs a value, 4 need manual action |
| Attack paths | **2**: *Remote takeover through the management plane* (break it: fix MGMT-003) and *Traffic steered through an open perimeter* (fix BOUNDARY-001). The page shows "checked against a positive and a negative configuration (commit 12f7e35)" |
| CVE context | IOS-XE **16.9**: 4 critical and 72 high CVEs in NVD; top five CVE-2020-3227 (9.8), CVE-2021-1619 (9.8), CVE-2019-1754, CVE-2020-3141, CVE-2020-3219 (8.8), with the caveat and a cache date of 2026-09-28 |

Decided FAILs and the lines they cite:

| Check | Severity | Lines |
|---|---|---|
| MGMT-001 Telnet enabled | critical | 75-79 |
| MGMT-003 Unrestricted management access | critical | 75-79 |
| MGMT-005 Plaintext / weak passwords | critical | 16 |
| BOUNDARY-001 Any-any permit | critical | 48 |
| MGMT-002 HTTP management | high | 27, 30 |
| MGMT-007 SSH version 1 | high | 27, 30 |
| MGMT-004 Default SNMP community | high | 53 |
| MGMT-011 SNMPv1/v2c | high | 53 |
| MGMT-008 No AAA | high | 15 |
| AUTH-001 No login lockout | high | (not configured) |
| AUTH-002 Weak password policy | medium | (not configured) |
| AUTH-003 Default `admin` account | medium | 16 |
| BOUNDARY-002 Source routing | medium | 22, 44 |
| BOUNDARY-004 Redirects / proxy-ARP (IOS defaults) | medium | 32-37 and 39-42 (both interfaces) |
| MGMT-006 Session timeout disabled | medium | 75-79 |

Passed: BOUNDARY-003, LOG-001, LOG-002, MGMT-009.

### 2.2 `backend/tests/fixtures/demo/juniper_edge_braces.conf`: brace-style Junos, no parser

| | |
|---|---|
| Read as | Unfamiliar device, generic analysis with shipped knowledge |
| Score (posture) | **45/100** (a limited assessment: it covers only what could be decided) |
| Checks decided (coverage) | **44%** (9 assessed, 14 undecided) |
| Risk | **HIGH 60/100** |
| Problems | **6** (1 critical, 3 high, 1 medium, 1 low), each "needs your command" (no fix is generated for an unconfirmed vendor) |
| Attack paths | none |

- **Decided FAILs:**
  - MGMT-001 Telnet (line 16), MGMT-002 HTTP management (18), MGMT-011 SNMPv2c (34) and AUTH-003 `admin` account (5);
  - MGMT-008 no AAA and MGMT-009 no login banner, read as absent because Junos knowledge knows how both are written.
- **Passed:**
  - MGMT-004: the community `jun-mon1tor` is not a default name;
  - MGMT-005: the password is a `$6$` hash;
  - MGMT-007: SSH version 2.

### 2.3 `backend/tests/fixtures/demo/aws_edge.tf`: Terraform (AWS), no parser

| | |
|---|---|
| Read as | Terraform, flattened in place; the 20 device-only checks are N/A |
| Score (posture) | **0/100** |
| Checks decided (coverage) | **67%** (2 of the 3 applicable checks) |
| Risk | **HIGH 60/100** |
| Problems | **2 critical**: MGMT-003 SSH open to `0.0.0.0/0` (line 6, the `ingress {` block) and BOUNDARY-001 any-protocol ingress from `0.0.0.0/0` (line 13) |
| Attack paths | none (no chain has every step failing) |
| Undecided | MGMT-010 (management from an untrusted interface): not read for cloud rules; MGMT-003 covers it |

## 3. Problems found by this run

1. **Fixed during this run.** On the Junos file, MGMT-004 first showed as *not checked*. The SNMP community was read
   correctly from its leaf line (34). The generic heuristic, however, also read the block header `community
   jun-mon1tor {` (line 33) as a second community, and the weakest assurance won. A header that names the object
   a per-object setting answered (`community …`, `user …`) is now marked as read. The score went 33 → 45 and
   coverage 36% → 44%. A regression test was added (`test_structured_braces.py`), and the benchmark is unchanged.
2. **Open, display only.** Cisco MGMT-002 (HTTP) and MGMT-007 (SSH v1) both cite lines 27 and 30, so the Overview
   card and the attack-path step for HTTP show `line 27: ip ssh version 1` first. The verdicts are right; the
   first cited line shown for HTTP should be `ip http server` (line 30).
3. **Open, wording.** The Cisco scan header says "19 of 20 checks decided", but the device card says "19 of 23".
   The header leaves out the 3 N/A checks and the card counts all 23.
4. **Setup note.** The first scan took about 60 s end to end, the later ones about 4 s. The first request after a
   backend start pays a one-time warm-up. The browser console showed errors only while the backend was still on
   the wrong port (8000); there were none during the scans.
