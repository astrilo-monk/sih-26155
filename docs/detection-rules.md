# Controls Reference

The 23 controls in `backend/app/controls/catalog.py`. Every control runs on every configuration. "Cisco" and
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
| MGMT-010 | Are management services kept off external (internet-facing) interfaces and zones? | Critical | N/A: IOS binds no management service to an interface (MGMT-003 asks about VTY sources) | SSH / HTTP(S) / Telnet / SNMP / FortiManager in WAN `allowaccess` (ping is not counted) | FortiGate: remove every management service from WAN `allowaccess` |
| MGMT-011 | Is SNMP limited to version 3, with no community-based (v1/v2c) access? | High | any `snmp-server community` (none = PASS by default) | any SNMP community block | Human: moving to SNMPv3 needs users and keys |
| AUTH-001 | Does the device limit failed login attempts (10 or fewer)? | High | `login block-for … attempts N`, `aaa local authentication attempts max-fail N` (none = FAIL) | `admin-lockout-threshold` (default 3) | Cisco: `login block-for 900 attempts 3 within 120` · FortiGate: `admin-lockout-threshold 3` |
| AUTH-002 | Does the device enforce a minimum password length of at least 8? | Medium | `security passwords min-length` (none = FAIL) | `config system password-policy` (`status enable`, `minimum-length`, default off) | Cisco: `security passwords min-length 12` · FortiGate: enable the policy, length 12 |
| AUTH-003 | Are administrative accounts renamed from vendor defaults (`admin`, `root`, `cisco` …)? | Medium | `username` | `config system admin` (none = the shipped `admin`) | Human: a named account needs new credentials |
| BOUNDARY-001 | Does every ACL / policy avoid permitting all traffic from any to any? | Critical | ACL entries | firewall policies (all addresses, service ALL) | Always human review |
| BOUNDARY-002 | Is IP source routing disabled? | Medium | `ip source-route` | `ip-src-routing` (default disable) | `no ip source-route` · `ip-src-routing disable` |
| BOUNDARY-003 | Are discovery protocols disabled on external interfaces? | Medium | CDP on WAN-identified interfaces | LLDP on WAN interfaces | `no cdp enable` · `lldp-transmission disable` |
| BOUNDARY-004 | Do routed interfaces refuse ICMP redirects, proxy-ARP and directed broadcasts? | Medium | per routed interface: `no ip redirects`, `no ip proxy-arp` (IOS default: both on, assurance DEFAULT), `ip directed-broadcast` | N/A | Cisco: add the three `no …` lines to the failing interfaces |
| LOG-001 | Are logs forwarded to a remote log server? | High | `logging host` | syslogd setting | Add the server (needs syslog server) |
| LOG-002 | Is the clock synchronized from authenticated NTP servers? | Medium | `ntp server`, `ntp authenticate` | NTP servers, `authentication` | Add key and authentication (needs key; server if none) |
| LOG-003 | Does every permitting firewall rule log what it matches? | Medium | N/A (ACL logging is not a benchmark item) | policy `logtraffic` (unset = `utm`; only `disable` fails) | FortiGate: `set logtraffic all` |
| CRYPTO-001 | Do VPN proposals avoid weak encryption, hashing and DH groups? | High | ISAKMP policies, transform sets | phase1-interface `proposal`, `dhgrp` | AES-256 / SHA-256 / DH 14 (VPN peers must match) |
| CRYPTO-002 | Do SSH / HTTPS management avoid weak ciphers, MACs and key exchange? | High | `ip ssh server algorithm encryption/mac/kex`, `ip http secure-ciphersuite` (none = NOT_CONFIGURED: the release default decides) | `strong-crypto` (default enable), `ssh-cbc-cipher` / `ssh-hmac-md5` / `ssh-kex-sha1` | Cisco: AES-CTR / SHA-2 / ECDH lists · FortiGate: `strong-crypto enable`, weak switches off |

Each control's framework mappings (NIST SP 800-53 Rev. 5, DISA NDM SRG, ISO/IEC 27001:2022 Annex A; CIS items for the confirmed vendor) are listed in the
catalog and shown in the Framework view. Remediation details: [architecture.md](architecture.md#10-remediation).
