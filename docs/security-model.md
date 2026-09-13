# Security Model

This document outlines how our app determines if a configuration is secure.

## How it works

We don't use AI to find vulnerabilities directly. AI is too unpredictable for core security scanning. Instead, our pipeline works like this:

1. **Parser:** Converts raw config text into a `NormalizedConfig` Python object.
2. **Rules Engine:** Runs deterministic Python functions against the `NormalizedConfig`. 
3. **Findings Generation:** If a rule triggers, it generates a `Finding` object.
4. **Scoring:** The total score is calculated based on the severity of the findings.

## Scoring System

Configs start with a score of 100. Points are deducted based on findings:
* **Critical:** -12 points
* **High:** -6 points
* **Medium:** -3 points
* **Low:** -1 point

Score is floored at 0.

## Implemented Rules

The engine currently runs 15 deterministic rules. The rule IDs below are the IDs returned by the API:

| Rule ID | Name | Severity | What it checks |
|---|---|---|---|
| MGMT-001 | Telnet enabled | Critical | Checks Cisco VTY transport and FortiGate interface services. |
| MGMT-002 | Insecure HTTP management | High | Checks Cisco HTTP and FortiGate WAN HTTP access. |
| MGMT-003 | Unrestricted management access | Critical | Checks missing Cisco VTY access classes and FortiGate WAN management services. |
| MGMT-004 | Weak or default SNMP communities | High/Critical | Checks default strings and unrestricted read-write communities. |
| MGMT-005 | Plaintext or weak passwords | Critical | Cisco-only check for plaintext, Type 7, and missing password encryption service. |
| MGMT-006 | Missing or disabled timeout | Medium | Checks Cisco VTY/console and long FortiGate admin timeouts. |
| MGMT-007 | Weak SSH configuration | High | Checks SSH version 1. |
| MGMT-008 | AAA not configured | High | Checks central AAA (Cisco `aaa new-model`); UNKNOWN for FortiGate, whose parser does not read AAA. |
| MGMT-009 | Missing login banner | Low | Checks Cisco login/MOTD and FortiGate pre-login banners. |
| BOUNDARY-001 | Overly permissive ACL/firewall rule | Critical | Checks Cisco IP any-any permits and FortiGate all-service permits. |
| BOUNDARY-002 | IP source routing enabled | Medium | Checks the global source-routing setting. |
| BOUNDARY-003 | CDP/LLDP on an external interface | Medium | Checks discovery protocols on WAN interfaces. |
| LOG-001 | No remote syslog | High | Checks whether a remote logging host exists. |
| LOG-002 | Missing or unauthenticated NTP | Medium | Checks NTP servers and authentication. |
| CRYPTO-001 | Weak VPN/IPsec cryptography | High | Checks DES, 3DES, MD5, and weak DH groups. |

Controls are declared in `backend/app/controls/catalog.py`, judged over security facts in `backend/app/controls/judges.py` and evaluated by `backend/app/controls/evaluate.py`. Vendor parsers and adaptive mappings become facts in `backend/app/facts/from_normalized.py`; `backend/app/analysis/engine.py` turns the results into findings.
