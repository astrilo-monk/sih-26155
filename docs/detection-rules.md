# Controls Reference

The 15 controls in `backend/app/controls/catalog.py`. Every control runs on every configuration. "Cisco" and
"FortiGate" mean a confirmed vendor profile; everything else goes through the generic path (heuristics and
confirmed recognizers, optional AI proposals).

| ID | Question | Severity | Cisco IOS facts | FortiGate facts | Remediation |
|---|---|---|---|---|---|
| MGMT-001 | Is cleartext Telnet disabled for remote management? | Critical | VTY `transport input` (implicit transport = UNKNOWN) | interface `allowaccess` | Cisco: `transport input ssh` on VTY ranges · FortiGate: remove `telnet` |
| MGMT-002 | Is cleartext HTTP management disabled? | High | `ip http server` | WAN `allowaccess` | Cisco: `no ip http server` · FortiGate: remove `http` on WAN |
| MGMT-003 | Is management access restricted to trusted sources? | Critical | VTY `access-class` | management services on WAN interfaces | Cisco: management ACL + `access-class` (needs subnet) · FortiGate: remove management services on WAN |
| MGMT-004 | Are SNMP communities free of default strings and unrestricted write access? | Critical / High | `snmp-server community` | SNMP community blocks | Comment out failing communities (FortiGate: whole nested block) |
| MGMT-005 | Are stored passwords protected with strong encoding? | Critical | enable / user password types, `service password-encryption` | not read (UNKNOWN) | Cisco: `service password-encryption` only; weak passwords → human review |
| MGMT-006 | Do idle management sessions time out? (≤ 15 min) | Medium | VTY / console `exec-timeout` | `admintimeout` (default 5) | Cisco: `exec-timeout 5 0` · FortiGate: `admintimeout 5` |
| MGMT-007 | Is SSH restricted to protocol version 2? | High | `ip ssh version` | `admin-ssh-v1` (default disable) | `ip ssh version 2` · `admin-ssh-v1 disable` |
| MGMT-008 | Is AAA enabled for administrative access? | High | `aaa new-model` | not read (UNKNOWN) | Cisco: AAA with local login only if a strong local account exists, else human review |
| MGMT-009 | Is a legal warning banner shown before login? | Low | `banner login` / `banner motd` | `pre-login-banner` (default disable) | Cisco: add `banner login` · FortiGate: `pre-login-banner enable` |
| BOUNDARY-001 | Does every ACL / policy avoid permitting all traffic from any to any? | Critical | ACL entries | firewall policies (all addresses, service ALL) | Always human review |
| BOUNDARY-002 | Is IP source routing disabled? | Medium | `ip source-route` | `ip-src-routing` (default disable) | `no ip source-route` · `ip-src-routing disable` |
| BOUNDARY-003 | Are discovery protocols disabled on external interfaces? | Medium | CDP on WAN-identified interfaces | LLDP on WAN interfaces | `no cdp enable` · `lldp-transmission disable` |
| LOG-001 | Are logs forwarded to a remote log server? | High | `logging host` | syslogd setting | Add the server (needs syslog server) |
| LOG-002 | Is the clock synchronized from authenticated NTP servers? | Medium | `ntp server`, `ntp authenticate` | NTP servers, `authentication` | Add key and authentication (needs key; server if none) |
| CRYPTO-001 | Do VPN proposals avoid weak encryption, hashing and DH groups? | High | ISAKMP policies, transform sets | phase1-interface `proposal`, `dhgrp` | AES-256 / SHA-256 / DH 14 (VPN peers must match) |

Each control's framework mappings (NIST SP 800-53 Rev. 5, DISA NDM SRG, ISO/IEC 27001:2022 Annex A; CIS items for the confirmed vendor) are listed in the
catalog and shown in the Framework view. Remediation details: [architecture.md](architecture.md#10-remediation).
