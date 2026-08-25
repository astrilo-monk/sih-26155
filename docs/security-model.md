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

## Planned Rules (The "SIH 15")

We plan to implement these 15 core rules in our engine:

| Rule ID | Name | Severity | What it checks |
|---|---|---|---|
| SEC-001 | Default Credentials Enabled | Critical | Checks for default admin accounts/passwords. |
| SEC-002 | Weak Password Encryption | High | Checks if Type 7 (Cisco) or weak hashing is used instead of strong hashing. |
| SEC-003 | Telnet Enabled | Critical | Checks if Telnet (port 23) is active instead of SSH. |
| SEC-004 | Insecure SNMP Version | High | Checks for SNMPv1/v2c instead of SNMPv3. |
| SEC-005 | Missing ACL on VTY Lines | High | Checks if remote access lines lack IP restrictions. |
| SEC-006 | Open DNS Resolver | Medium | Checks if the device acts as a public DNS resolver. |
| SEC-007 | Missing Password Prefix | Low | Checks if passwords lack minimum complexity settings. |
| SEC-008 | Unencrypted Traffic on HTTP | Medium | Checks if web admin is enabled on HTTP instead of HTTPS. |
| SEC-009 | Permissive Any-Any Rule | Critical | Checks firewall policies for `permit any any` or equivalent. |
| SEC-010 | Missing Logging | Medium | Checks if syslog/logging to a central server is disabled. |
| SEC-011 | Unused Interfaces UP | Low | Checks if interfaces without IPs/configs are administratively UP. |
| SEC-012 | Weak IKE/IPSec Policies | High | Checks for DES/3DES or MD5 in VPN configs. |
| SEC-013 | Missing BGP Authentication | Medium | Checks if BGP peers lack MD5/SHA authentication. |
| SEC-014 | SNMP Public Community | High | Checks if the default `public` or `private` community strings are used. |
| SEC-015 | NTP Unauthenticated | Low | Checks if NTP is running without authentication keys. |

*(Note: Currently in the planning phase. The rules engine logic hasn't been coded yet.)*
