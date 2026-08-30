# Project Audit Report: NetAuditAI

This document provides a formal technical audit of the NetAuditAI project. The audit reviews the current architecture, documentation, parsing stability, and testing coverage to ensure readiness for the SIH hackathon demo.

## Executive Summary
The project correctly employs a deterministic Python rules engine utilizing a `NormalizedConfig` data model, which allows it to scale across multiple vendors without duplicated effort. However, several critical parser bugs and significant documentation drift were discovered during this audit.

## 1. Documentation Drift & Rule ID Mapping

**Severity:** High
**Finding:** The original documentation (`docs/detection-rules.md`, `docs/api.md`) heavily referenced placeholder IDs (`SEC-001` through `SEC-015`). The codebase, however, uses categorized semantic IDs (`MGMT-001`, `BOUNDARY-001`, etc.) and implements different logic than originally planned.

**Rule Mapping:**
The following table maps the currently implemented rules to their old documented placeholders where applicable. 

| Current Rule ID | Old Doc ID | Rule Name | Severity | Detection Behavior |
| --- | --- | --- | --- | --- |
| MGMT-001 | SEC-003 | Insecure Management Protocol (Telnet) Enabled | Critical | Flags 'transport input telnet/all' (Cisco) or 'telnet' on allowed services (FortiGate). |
| MGMT-002 | SEC-008 | Insecure HTTP Management Enabled | High | Flags HTTP server active (Cisco) or allowed on WAN (FortiGate). |
| MGMT-003 | SEC-005 | Unrestricted Management Access | Critical | Flags VTY lines without access-class (Cisco) or WAN interface allowing mgmt (FortiGate). |
| MGMT-004 | SEC-004, SEC-014 | Weak or Default SNMP Community Strings | High/Crit | Flags default strings like 'public' or RW strings without an ACL. |
| MGMT-005 | SEC-001, SEC-002 | Plaintext or Weakly Encrypted Passwords | Critical | Flags Type 0/7 passwords, missing 'service password-encryption'. |
| MGMT-006 | *New* | Missing or Disabled Session Timeout | Medium | Flags VTY/Console lines without timeout or >15 mins on FortiGate. |
| MGMT-007 | *New* | SSH Version 1 or Weak SSH Configuration | High | Flags SSH version 1 configurations. |
| MGMT-008 | *New* | AAA Not Configured | High | Flags missing 'aaa new-model' on Cisco. |
| MGMT-009 | *New* | Missing Login Banner | Low | Flags missing login/motd warning banners. |
| BOUNDARY-001 | SEC-009 | Overly Permissive Firewall/ACL Rules | Critical | Flags IP permits with 'any' source and 'any' destination. |
| BOUNDARY-002 | *New* | IP Source Routing Enabled | Medium | Flags active IP source routing. |
| BOUNDARY-003 | *New* | Discovery Protocol Enabled on External Int. | Medium | Flags CDP/LLDP on WAN interfaces. |
| LOG-001 | SEC-010 | No Remote Syslog Server Configured | High | Flags absence of remote syslog hosts. |
| LOG-002 | SEC-015 | NTP Not Configured or Unauthenticated | Medium | Flags missing NTP auth or missing servers. |
| CRYPTO-001 | SEC-012 | Weak VPN/IPsec Cryptographic Algorithms | High | Flags weak DES/3DES/MD5 in ISAKMP proposals. |

*Note: Rules SEC-006, SEC-007, SEC-011, and SEC-013 from the original documentation were never implemented and have been replaced by the *New* rules above.*

**Remediation Action:** All documentation (`detection-rules.md`, `api.md`) has been updated to reflect the `Current Rule ID` column as the single source of truth.

## 2. Parser Issues

### The Cisco Extended ACL `any-any` Bug
**Severity:** Critical
**Finding:** The `CiscoIOSParser` was unable to properly parse source and destination IPs for extended access lists, defaulting to discarding them.
**Evidence:** The initial implementation on line 263 was `entry.protocol = rest.split()[0] if rest.split() else "ip"`, ignoring the source/destination string entirely.
**Impact:** Rule `BOUNDARY-001` (Overly Permissive Rules) was silently failing for all Cisco configurations, resulting in dangerous false negatives.
**Remediation Action:** Rewrote the extended ACL parser to correctly tokenize protocol, source, and destination strings. `permit ip any any` and `host` configurations are now correctly ingested into the `NormalizedConfig` model.

## 3. Security Issues: AI Remediation Strategy
**Severity:** High
**Finding:** The initial design documents claimed that Gemini AI would dynamically generate CLI remediation commands. 
**Evidence:** `docs/ai-design.md` stated: *"Gemini generates the exact CLI commands needed to fix the issue."*
**Impact:** Using an LLM to dynamically generate network commands creates severe operational risks. If the AI hallucinates invalid syntax or incorrect interface names, deploying those commands could cause catastrophic network outages.
**Remediation Action:** Confirmed the codebase successfully uses a **deterministic template engine** (`remediation/engine.py`) instead of AI generation. Updated `docs/ai-design.md` and `docs/demo.md` to reflect this safer architectural decision, clarifying that templates significantly reduce the risk of malformed commands.

## 4. Testing Gaps
**Severity:** Medium
**Finding:** While `test_pipeline.py` checked overarching pipeline logic, there were zero unit tests for individual parsers or boundary constraints.
**Evidence:** The `any-any` bug slipped through because no test specifically asserted that `permit ip any any` would trigger `BOUNDARY-001`.
**Remediation Action:** Added `tests/test_cisco_acl.py` with granular assertions for ACL parsing (`permit ip any any`, `permit tcp any any`, restricted hosts) and integrated assertions for `BOUNDARY-001` into the main test suite.

## 5. Demo Risks
**Severity:** Low
**Finding:** If presenters follow the original script in `docs/demo.md`, they will make incorrect claims to the judges regarding AI capabilities (claiming AI generates the fix, when it actually uses templates). Additionally, they would have attempted to search for `SEC-003` which no longer exists in the API payload.
**Remediation Action:** The demo script has been patched to align with the actual implementation. It now guides presenters to demonstrate the deterministic templates as a distinct security advantage over standard AI wrappers.

## 6. Recommended Next Steps
- Implement unit tests for the Fortinet Parser (`fortinet.py`) to ensure feature parity with Cisco.
- Add additional regression tests for `CRYPTO-001` and `MGMT-004`.
- Proceed with frontend dashboard implementation now that the backend models are stabilized.
