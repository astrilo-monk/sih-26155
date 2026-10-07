"""Generate docs/detection-rules.md from the control catalog, the shipped seeds and the recipe table.

    cd backend && python scripts/build_detection_rules.py        # rewrites docs/detection-rules.md

Framework mappings, seed counts and recipe availability come from the code. The per-control notes (``N``) are
hand-written against app/controls/judges.py and app/facts/from_normalized.py: update them when a judge, a parser
fact or a seed family changes, then rerun.
"""
import collections
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from app.controls.catalog import CONTROLS  # noqa: E402
from app.remediation.recipes import RECIPES  # noqa: E402

FW_NAME = {"NIST_800_53": "NIST SP 800-53 Rev. 5", "CIS": "CIS", "DISA_STIG": "DISA NDM SRG", "ISO_27001": "ISO/IEC 27001:2022"}
VENDOR = {"cisco_ios": "Cisco IOS", "fortinet": "FortiGate"}

seeds = json.loads((BACKEND / "data" / "seed_recognizers.json").read_text(encoding="utf-8"))["recognizers"]
seed_by_pred = collections.defaultdict(collections.Counter)
SUBJECT = {"MGMT-001": "telnet", "MGMT-002": "http"}
seed_subject = collections.defaultdict(collections.Counter)
for r in seeds:
    seed_by_pred[r["predicate"]][r["vendor"]] += 1
    seed_subject[(r["predicate"], r.get("subject"))][r["vendor"]] += 1


def seeds_for(c):
    if c.control_id in SUBJECT:
        return collections.Counter(seed_subject[(c.needs[0], SUBJECT[c.control_id])])
    total = collections.Counter()
    for p in c.needs:
        total.update(seed_by_pred[p])
    return total

# Hand-written, checked against app/controls/judges.py and app/facts/from_normalized.py
N = {
"MGMT-001": dict(
    reads="`mgmt.remote_access.protocol_enabled` with subject `telnet`",
    pass_="every fact says Telnet is off",
    fail="a fact says Telnet is on (one FAIL per VTY range, interface or block that allows it)",
    unknown="Telnet is mentioned but on/off cannot be read; IOS VTY lines with no `transport input` (the default differs by release)",
    cisco="VTY `transport input` (`telnet` or `all` = on; `ssh` only = off)",
    forti="`telnet` in an interface `allowaccess` list",
    generic="Junos `services { telnet; }` / `set system services telnet`, PAN-OS `disable-telnet no`, Huawei `telnet server enable` / `undo telnet server enable`, RouterOS `/ip service set telnet disabled=yes`, Aruba `no telnet server`, EXOS `disable telnet`, Gaia `set telnet-server enabled false`, Arista `no management telnet`, NX-OS `feature telnet`, Dell OS10 `ip telnet server enable` / `no …`, IOS-XR `telnet vrf … ipv4 server`; documented defaults: NX-OS and ASA Telnet off unless a line enables it",
    fix_cisco="`transport input ssh` on every failing VTY range",
    fix_forti="remove `telnet` from `allowaccess` on the interface",
    fix_generic="seed write-back flips the slot (`disable-telnet no` → `yes`, `telnet yes` → `no`); a removal candidate (`delete system services telnet`) can be derived",
),
"MGMT-002": dict(
    reads="`mgmt.remote_access.protocol_enabled` with subject `http`",
    pass_="HTTP management is off",
    fail="cleartext HTTP management is on",
    unknown="HTTP is mentioned but its state cannot be read",
    cisco="`ip http server` / `no ip http server`",
    forti="`http` in a WAN interface `allowaccess`",
    generic="PAN-OS `disable-http no` and interface-management profile `http no`, Junos `set system services web-management http`, Huawei `http server enable` / `undo …`, RouterOS `set www disabled=yes`, Arista `management http-commands`, Gaia `set web-server enabled false`, EXOS `disable web`, Aruba `no http vrf default`, NX-OS `nxapi http port`",
    fix_cisco="`no ip http server` (and `ip http secure-server`)",
    fix_forti="remove `http` from `allowaccess` on WAN interfaces",
    fix_generic="seed write-back flips the slot; removal candidate derivable",
),
"MGMT-003": dict(
    reads="`mgmt.remote_access.source_restricted`",
    pass_="management access is limited to named sources",
    fail="a VTY range has no `access-class`, a management rule is open to `0.0.0.0/0`, or a cloud rule allows SSH / RDP / Telnet from anywhere",
    unknown="relational: with no fact at all the control is UNKNOWN, never NOT_CONFIGURED",
    cisco="VTY `access-class` (per range; the first open range is the failing scope)",
    forti="management services on WAN interfaces",
    generic="PAN-OS `permitted-ip`, Junos `allow-address` / `allow-sources`, Arista `ip access-group` under `management ssh`, EXOS SSH `access-profile`, NX-OS `access-class … in`; Terraform and cloud JSON rules open to `0.0.0.0/0` or `::/0` on port 22 / 23 / 3389, Huawei `acl … inbound` under `user-interface vty`, AOS-CX `apply access-list ip … control-plane`, Dell OS10 `ip access-group … mgmt|data in` under `control-plane`, IOS-XR `ssh server vrf … ipv4 access-list`",
    fix_cisco="a management ACL from `management_subnet` plus `access-class MGMT in` on each VTY range",
    fix_forti="remove management services from WAN interfaces",
    fix_generic="write-back replaces the wildcard with the operator's `management_subnet`; cloud rules get no generated command",
),
"MGMT-004": dict(
    reads="`snmp.community` (value: `{name, permission, acl}`)",
    pass_="no community, or none with a default string and no read-write community without an ACL",
    fail="a default string (`public`, `private`, `community`, `snmp`, `default`), or RW without an ACL. Severity is critical for RW, high for RO",
    unknown="a community line that cannot be read",
    cisco="`snmp-server community NAME RO|RW [acl]`; none configured = PASS by documented default",
    forti="`config system snmp community` entries; none = PASS by documented default",
    generic="seed-only `{community:RO}` / `{community:RW}` slots (read at scan time, never stored) for Junos, NX-OS, Arista (also read on Dell OS10), Huawei, PAN-OS, Gaia, Aruba, EXOS, RouterOS, SONiC, Cumulus, VyOS (read-only)",
    fix_cisco="comment out the failing `snmp-server community` lines",
    fix_forti="comment out the failing community block (the whole nested block)",
    fix_generic="removal candidate only; cannot be taught (the line holds the secret)",
),
"MGMT-005": dict(
    reads="`auth.password.storage` (subject `enable`, `user <name>`, `console`) and `auth.password.encryption_service`",
    pass_="every stored password uses a strong type (`secret`, `type5_md5`, `type8_sha256`, `type9_scrypt`, `encrypted`, `hashed`) and the encryption service is on",
    fail="a `plaintext`, `type0` or `type7` password (critical), or no `service password-encryption` (high)",
    unknown="a storage type that cannot be classified",
    cisco="`enable secret|password [type]`, `username … secret|password [type]`, `service password-encryption`",
    forti="not read: UNKNOWN with the reason \"the fortinet parser does not read …\"",
    generic="password lines read with `{enum:type}` slots so the type is read and the value never stored (Arista, Huawei, Aruba, EXOS, NX-OS, Junos `encrypted-password`, PAN-OS `phash`, RouterOS `password=` read as plaintext), Gaia `password-hash`, ASA `pbkdf2` / `encrypted`, IOS-XR `secret 5|8|9|10` / `password 7`, FortiSwitchOS `password ENC`",
    fix_cisco="`service password-encryption` only; changing a weak password needs a person (`manual_review`)",
    fix_forti="none",
    fix_generic="none: a new password must come from a person",
),
"MGMT-006": dict(
    reads="`mgmt.session.idle_timeout` (unit `min`)",
    pass_="every scope times out within the limit (15 minutes, or the organisation policy's tighter value)",
    fail="no timeout, `0` (disabled), or longer than the limit",
    unknown="a timeout with no known unit",
    cisco="VTY and console `exec-timeout M [S]` (worst VTY range is the scope); no timeout = FAIL (CIS requires it set)",
    forti="`set admintimeout N`; default 5 minutes (PASS by documented default)",
    generic="Junos `idle-timeout`, PAN-OS `idle-timeout` (minutes), Arista `idle-timeout` (minutes), Huawei, Gaia (`session-timeout`, seconds), EXOS (`inactivity-timeout`, seconds), NX-OS, ASA `ssh timeout` / `console timeout` / `http server idle-timeout` (minutes), FortiSwitchOS `admintimeout`, AOS-CX top-level `session-timeout` (minutes), Dell OS10 top-level `exec-timeout` (seconds), IOS-XR `exec-timeout <min> 0`, ASA `telnet timeout`",
    fix_cisco="`exec-timeout 5 0` on failing lines",
    fix_forti="`set admintimeout 5`",
    fix_generic="write-back sets 10 minutes in the dialect's own unit; never a removal (a threshold control is not derivable)",
),
"MGMT-007": dict(
    reads="`mgmt.ssh.version`",
    pass_="version 2",
    fail="version 1 (including `v1` / `1.99` compatibility read as 1)",
    unknown="a version that cannot be interpreted",
    cisco="`ip ssh version N`; absent = NOT_CONFIGURED (no default assumed: it differs by release)",
    forti="`set admin-ssh-v1 enable|disable`; default disable = version 2",
    generic="Junos `protocol-version v2`, PAN-OS, Arista, ASA `ssh version 2`, IOS-XR `ssh server v2`, FortiSwitchOS `admin-ssh-v1 enable|disable`; documented defaults: NX-OS and EXOS support SSH version 2 only",
    fix_cisco="`ip ssh version 2`",
    fix_forti="`set admin-ssh-v1 disable`",
    fix_generic="write-back `protocol-version v1` → `v2`",
),
"MGMT-008": dict(
    reads="`auth.central_aaa.enabled`",
    pass_="central AAA (TACACS+ / RADIUS) is enabled",
    fail="no AAA",
    unknown="AAA mentioned but not readable",
    cisco="`aaa new-model`",
    forti="not read: UNKNOWN",
    generic="Junos `authentication-order`, `tacplus-server`, `radius-server`; PAN-OS TACACS+ / RADIUS profiles; NX-OS; ASA (`LOCAL` alone is not central); SONiC and Cumulus TACACS+ entries; VyOS `set system login radius-server`; learned absence fails it for an understood dialect; Huawei `authentication-mode hwtacacs|radius|local`, Gaia `aaa tacacs-servers state`, EXOS `enable tacacs` / `radius mgmt-access`, RouterOS `use-radius`, FortiSwitchOS `remote-auth`",
    fix_cisco="AAA with local login only if a strong local account exists, otherwise `manual_review` (lockout risk)",
    fix_forti="none",
    fix_generic="never added: AAA needs a shared secret",
),
"MGMT-009": dict(
    reads="`banner.login.present`",
    pass_="a login or MOTD banner exists",
    fail="no banner (`NOT_SET`), or the FortiGate pre-login banner is disabled",
    unknown="a banner statement that cannot be read",
    cisco="`banner login` / `banner motd`",
    forti="`set pre-login-banner enable|disable`; default disable = FAIL",
    generic="Junos `message`, PAN-OS `login-banner`, Arista `banner login`, Huawei `header login`, RouterOS `/system note`, Aruba, EXOS, Gaia, Dell OS10 `banner login ^C`, VyOS `set system login banner pre-login`; learned absence fails it for an understood dialect, NX-OS `banner motd`, IOS-XR `banner login`, FortiSwitchOS `pre-login-banner`",
    fix_cisco="adds a fixed legal-warning `banner login`",
    fix_forti="`set pre-login-banner enable`",
    fix_generic="added from `banner_text` with the dialect's own template",
),
"MGMT-010": dict(
    reads="`mgmt.remote_access.exposed_externally` (scope: interface or zone)",
    pass_="no management service is reachable on an external interface",
    fail="SSH, HTTP(S), Telnet, SNMP or FortiManager (`fgfm`) access on a WAN interface or untrusted zone (ping is not counted)",
    unknown="exposure mentioned but not readable",
    cisco="N/A: IOS binds no management service to an interface (MGMT-003 asks about VTY sources)",
    forti="management services in a WAN interface's `allowaccess`",
    generic="Junos `host-inbound-traffic system-services` on an `untrust` / `outside` / `internet` zone",
    fix_cisco="none",
    fix_forti="remove every management service from WAN `allowaccess`",
    fix_generic="removal candidate (cites only the first exposing service line: see the roadmap)",
),
"MGMT-011": dict(
    reads="`snmp.community`",
    pass_="no community at all",
    fail="any community exists: v1/v2c sends it in cleartext with no per-user login",
    unknown="never: any community fact fails",
    cisco="any `snmp-server community` (none = PASS by default)",
    forti="any SNMP community block",
    generic="the same community seeds as MGMT-004",
    fix_cisco="`manual_review`: SNMPv3 users and keys are the operator's to choose",
    fix_forti="the same",
    fix_generic="removal candidate",
),
"AUTH-001": dict(
    reads="`auth.login.max_attempts`",
    pass_="1 to 10 failed attempts before lockout or disconnect (or the policy's tighter limit)",
    fail="no limit, `0`, or more than the limit",
    unknown="a limit that cannot be read",
    cisco="`login block-for … attempts N`, `aaa local authentication attempts max-fail N`; none = FAIL",
    forti="`set admin-lockout-threshold N`; default 3 (PASS by documented default)",
    generic="Junos `retry-options tries-before-disconnect`, Aruba `ssh server max-auth-attempts`, PAN-OS `admin-lockout failed-attempts`, ASA `aaa local authentication attempts max-fail`, NX-OS `ssh login-attempts`, Arista `aaa authentication policy lockout failure`, Dell OS10 `password-attributes max-retry`, FortiSwitchOS `admin-lockout-threshold`, Huawei `ssh server authentication-retries`, Gaia `deny-on-fail` (off by default: a reviewed factory default), EXOS `max-failed-logins` / `lockout-on-login-failures`; every limit is its own fact and the weakest decides",
    fix_cisco="`login block-for 900 attempts 3 within 120`",
    fix_forti="`set admin-lockout-threshold 3`",
    fix_generic="write-back sets 3",
),
"AUTH-002": dict(
    reads="`auth.password.min_length`",
    pass_="at least 8 characters (or the policy's longer minimum)",
    fail="no minimum, or below it",
    unknown="a length that cannot be read",
    cisco="`security passwords min-length N`; none = FAIL",
    forti="`config system password-policy` with `status enable` and `minimum-length`; default off = FAIL",
    generic="Junos `password minimum-length`, PAN-OS `password-complexity minimum-length` (and its reviewed factory default: off), ASA `password-policy minimum-length`, Gaia `set password-controls min-password-length`, NX-OS `userpassphrase min-length`, Arista `password minimum length` (under `management security`), Dell OS10 `password-attributes min-length`, EXOS `password-policy min-length`, RouterOS `minimum-password-length`, FortiSwitchOS `minimum-length`",
    fix_cisco="`security passwords min-length 12`",
    fix_forti="enable the password policy with length 12",
    fix_generic="write-back sets 12",
),
"AUTH-003": dict(
    reads="`auth.account.name` (scope: the account)",
    pass_="no account uses a default name",
    fail="an account named `admin`, `administrator`, `root`, `cisco`, `manager` or `vyos` (lexicon `DEFAULT_ACCOUNT_NAMES`)",
    unknown="an account name that cannot be read",
    cisco="`username NAME …`; no users = PASS",
    forti="`config system admin` → `edit NAME`; no section = the shipped `admin` (FAIL by documented default)",
    generic="value table of default names, seed-only (teaching does not draft value tables): Junos `login user … class`, PAN-OS `mgt-config users … superuser yes`, Aruba, Arista, EXOS, Huawei, Dell OS10 `username … role`, VyOS `set system login user … authentication`, Gaia `set user … password-hash`, ASA `username … privilege`, NX-OS `username … role`, RouterOS `/user add|set`",
    fix_cisco="`manual_review`: a named account needs new credentials",
    fix_forti="the same",
    fix_generic="removal candidate",
),
"BOUNDARY-001": dict(
    reads="`boundary.policy.permit_any` (scope: the ACL or policy)",
    pass_="no rule permits any source to any destination for any service",
    fail="an any-to-any permit",
    unknown="relational: no rule found at all, or a rule that cannot be resolved",
    cisco="numbered and named ACL entries (`permit ip any any`)",
    forti="`config firewall policy` with `all` addresses and service `ALL`, action accept",
    generic="heuristic rule composition across statements (Junos, PAN-OS policies); seeds for Arista, ASA, Huawei, Aruba, EXOS, RouterOS, Gaia, NX-OS; Terraform and cloud JSON any-protocol rules from anywhere, Dell OS10 `seq N permit ip any any`, IOS-XR `permit ipv4 any any`",
    fix_cisco="always `manual_review`: a replacement rule needs the intended traffic",
    fix_forti="the same",
    fix_generic="removal candidate (deleting a rule is a decision a person must own)",
),
"BOUNDARY-002": dict(
    reads="`boundary.source_routing.enabled`",
    pass_="source routing is off",
    fail="source routing is on",
    unknown="mentioned but not readable",
    cisco="`ip source-route` / `no ip source-route`; absent = NOT_CONFIGURED (the default differs by release)",
    forti="`set ip-src-routing`; default disable",
    generic="Arista, Huawei, Gaia, VyOS `set firewall ip-src-route`, RouterOS `accept-source-route` (and its default: off), EXOS `enable ip-option …-source-route` and PAN-OS zone protection `discard-…-source-routing no` (read when they fail only: one option says nothing of the other)",
    fix_cisco="`no ip source-route`",
    fix_forti="`set ip-src-routing disable`",
    fix_generic="write-back flips the slot",
),
"BOUNDARY-003": dict(
    reads="`boundary.discovery_protocol.enabled` with subject `cdp` or `lldp`",
    pass_="off globally, or off on every external interface",
    fail="on for an interface identified as external",
    unknown="on, but no interface is identified as external",
    cisco="`cdp run` / `no cdp run` and per-interface CDP on WAN-identified interfaces",
    forti="`lldp-transmission` on WAN interfaces",
    generic="LLDP seeds for Junos, Arista, Huawei, Gaia, EXOS, RouterOS, PAN-OS, NX-OS; tied to an interface only when an external-named zone holds it or names it in its `interface` block; elsewhere a per-interface line is read and stays undecided; VyOS LLDP off by default (documented)",
    fix_cisco="`no cdp enable` on the failing interfaces",
    fix_forti="`set lldp-transmission disable`",
    fix_generic="write-back flips the slot",
),
"BOUNDARY-004": dict(
    reads="`boundary.interface.unsafe_service` with subject `redirects`, `proxy-arp` or `directed-broadcast` (scope: interface)",
    pass_="all three off on every routed interface",
    fail="any of them on",
    unknown="mentioned but not readable",
    cisco="per routed interface: `no ip redirects`, `no ip proxy-arp` (IOS default: both on, assurance `default`), `ip directed-broadcast`",
    forti="N/A (optional feature a confirmed parser found none of)",
    generic="Arista / NX-OS interface `ip redirects`, `ip proxy-arp`, `ip directed-broadcast` (switched on: decided; switched off on one interface: undecided, the others keep the default); device-wide: Junos `set system no-redirects`, Huawei `undo icmp redirect send`, AOS-CX `no ip icmp redirect`, RouterOS `send-redirects`, VyOS `set firewall send-redirects`, EXOS `disable icmp redirects vlan all`",
    fix_cisco="add the three `no …` lines to the failing interfaces",
    fix_forti="none",
    fix_generic="removal candidate",
),
"LOG-001": dict(
    reads="`log.remote.destination` (value: list of hosts)",
    pass_="logs go to at least one remote host (and only approved hosts when a policy names them)",
    fail="no remote destination (high), or a destination not on the policy's list (medium)",
    unknown="a destination line that cannot be read",
    cisco="`logging host X` / `logging X.X.X.X`",
    forti="`config log syslogd setting` with `status enable` and `server`",
    generic="13 dialects including PAN-OS syslog server profiles, Junos `syslog host`, SONiC `SYSLOG_SERVER`, Cumulus; learned absence fails it for an understood dialect",
    fix_cisco="add `logging host` from `syslog_server`",
    fix_forti="enable syslogd with `syslog_server`",
    fix_generic="added from `syslog_server` with the dialect's own template",
),
"LOG-002": dict(
    reads="`time.ntp.server` (list of servers) and `time.ntp.authenticated`",
    pass_="servers configured and authentication on",
    fail="no servers, authentication off, or a server not on the policy's list",
    unknown="servers configured but authentication cannot be read",
    cisco="`ntp server X`, `ntp authenticate`",
    forti="`config system ntp` `authentication`, `config ntpserver` entries",
    generic="NTP server seeds for 9 dialects (SONiC most), authentication seeds for Arista (`ntp authenticate`, `ntp authenticate servers`), Gaia, Aruba, Huawei, PAN-OS; Junos / VyOS `set system ntp server`; learned absence for servers; authentication also Junos `trusted-key`, IOS-XR `authenticate` / `trusted-key`, EXOS `enable ntp authentication`, FortiSwitchOS; documented default: VyOS 1.3 has no NTP authentication",
    fix_cisco="add key and authentication (needs `ntp_key_id`, `ntp_key`; `ntp_server` if none)",
    fix_forti="enable authentication with the key",
    fix_generic="never added: NTP authentication needs a key the recognizer does not describe",
),
"LOG-003": dict(
    reads="`boundary.policy.logging` (scope: the rule)",
    pass_="every permitting rule logs",
    fail="a permitting rule with logging off",
    unknown="mentioned but not readable",
    cisco="N/A (ACL logging is not a benchmark item; optional feature)",
    forti="policy `logtraffic` (unset means `utm`; only `disable` fails)",
    generic="PAN-OS rule `log-end`",
    fix_cisco="none",
    fix_forti="`set logtraffic all` on the failing policies",
    fix_generic="none generated (a requirement cannot be met by removal)",
),
"CRYPTO-001": dict(
    reads="`crypto.ipsec.proposal` (value: `{encryption, hash, dh_group}`)",
    pass_="no proposal uses DES / 3DES, MD5 or DH group 1, 2 or 5",
    fail="any weak algorithm in any proposal",
    unknown="a proposal that does not state its encryption (the platform default applies)",
    cisco="ISAKMP policies (`encr`, `hash`, `group`), transform sets",
    forti="phase1-interface `proposal`, `dhgrp`",
    generic="seeds read a proposal written one algorithm per line (Junos, PAN-OS, Huawei, ASA, VyOS): each line's table names the part it states and a weak part on any line fails; a list on one line is not read; heuristics otherwise",
    fix_cisco="upgrades ISAKMP policies and transform sets to AES-256 / SHA-256 / DH 14; warns that VPN peers must match",
    fix_forti="removes weak proposals (DES / 3DES / MD5) and DH groups 1, 2, 5 from the failing phase1 interfaces",
    fix_generic="none",
),
"CRYPTO-002": dict(
    reads="`mgmt.crypto.weak_allowed`",
    pass_="management SSH / HTTPS accepts no weak algorithm",
    fail="DES, 3DES, RC4, CBC ciphers, MD5 MACs or DH group 1 allowed",
    unknown="mentioned but not readable",
    cisco="`ip ssh server algorithm encryption|mac|kex …`, `ip http secure-ciphersuite …`; no list = NOT_CONFIGURED (the release decides)",
    forti="`strong-crypto` (default enable), `ssh-cbc-cipher`, `ssh-hmac-md5`, `ssh-kex-sha1`",
    generic="RouterOS `/ip ssh set strong-crypto=`, VyOS `set service ssh ciphers` / `macs` (weak ones only: CBC, 3DES, arcfour, blowfish, cast, MD5), FortiSwitchOS `strong-crypto`, Junos `ciphers` / `macs` / `key-exchange`, NX-OS `ssh cipher-mode weak` (default: CTR only), ASA `ssh cipher encryption` (every predefined level, and the default, includes CBC), Gaia `cipher|mac|kex … on`, PAN-OS a CBC cipher in an SSH server profile; one weak algorithm makes the answer weak",
    fix_cisco="replaces each weak list with AES-CTR ciphers, SHA-2 MACs and ECDH / DH group 14 key exchange; an HTTPS cipher-suite list goes to `manual_review`",
    fix_forti="`set strong-crypto enable`, weak switches off",
    fix_generic="removal candidate",
),
}

out = []
w = out.append
w("""# Controls Reference

The 23 security checks in `backend/app/controls/catalog.py`, how each one is decided, which configuration lines feed
it on every path, how it is fixed, and which framework requirements it answers.

This file is generated by `backend/scripts/build_detection_rules.py` from the catalog, the shipped recognizers and
the recipe table, plus hand-written notes checked against `app/controls/judges.py` and `app/facts/from_normalized.py`. Framework mappings, seed counts and
recipe availability are therefore exactly what the code ships.

**How to read a section**

* **Reads**: the predicate(s) the check consumes ([data-model.md](data-model.md#predicates)).
* **PASS / FAIL / UNKNOWN when**: what the judge decides for one fact. Combination across facts is always: any FAIL →
  FAIL per failing scope; else any UNKNOWN → UNKNOWN; else PASS with a cited line or a documented default; else
  NOT_CONFIGURED (or N_A / UNKNOWN, see [architecture.md §6](architecture.md#6-controls-and-controlresult)).
* **Cisco IOS / FortiGate**: what the confirmed parser reads. **Generic path**: what shipped recognizers read for
  other dialects (heuristics may read more, provisionally).
* **Fix**: the deterministic recipe for a confirmed vendor, and what an unconfirmed vendor can get.
* "Policy" means the organisation policy can tighten the limit ([policy.md](policy.md)).

---

## Summary

| ID | Severity | Kind | Check | Recipes | Shipped seeds |
|---|---|---|---|---|---|""")
for c in CONTROLS.values():
    vendors = sorted(VENDOR[v.value] for (cid, v) in RECIPES if cid == c.control_id)
    nseeds = sum(seeds_for(c).values())
    w(f"| [{c.control_id}](#{c.control_id.lower()}) | {c.severity.value.capitalize()} | {c.kind.value} | "
      f"{c.title} | {', '.join(vendors) or '-'} | {nseeds} |")

w("""
```mermaid
flowchart LR
    subgraph MGMT["Management plane"]
        M1["MGMT-001 Telnet"]
        M2["MGMT-002 HTTP"]
        M3["MGMT-003 source restriction"]
        M4["MGMT-004 SNMP strings"]
        M5["MGMT-005 password storage"]
        M6["MGMT-006 idle timeout"]
        M7["MGMT-007 SSH v2"]
        M8["MGMT-008 AAA"]
        M9["MGMT-009 banner"]
        M10["MGMT-010 external exposure"]
        M11["MGMT-011 SNMPv1/v2c"]
    end
    subgraph AUTH["Authentication"]
        A1["AUTH-001 lockout"]
        A2["AUTH-002 password length"]
        A3["AUTH-003 default account"]
    end
    subgraph BND["Boundary"]
        B1["BOUNDARY-001 any-any"]
        B2["BOUNDARY-002 source routing"]
        B3["BOUNDARY-003 CDP/LLDP"]
        B4["BOUNDARY-004 redirects, proxy-ARP"]
    end
    subgraph LOG["Logging and time"]
        L1["LOG-001 remote syslog"]
        L2["LOG-002 NTP"]
        L3["LOG-003 rule logging"]
    end
    subgraph CRY["Cryptography"]
        C1["CRYPTO-001 IPsec"]
        C2["CRYPTO-002 SSH / HTTPS"]
    end
```

### Severity weights

| Severity | Weight in posture | Controls |
|---|---|---|""")
by_sev = collections.defaultdict(list)
for c in CONTROLS.values():
    by_sev[c.severity.value].append(c.control_id)
weights = {"critical": 10, "high": 6, "medium": 3, "low": 1}
for s in ("critical", "high", "medium", "low"):
    w(f"| {s.capitalize()} | {weights[s]} | {', '.join(by_sev[s])} ({len(by_sev[s])}) |")
w("""
A failing result can carry its own severity (MGMT-004 is critical for a read-write community, high for read-only;
MGMT-005 high for a missing encryption service, critical for a weak password; LOG-001 / LOG-002 medium for an
unapproved server). The posture weight uses the worst failing severity.

---
""")

for c in CONTROLS.values():
    n = N[c.control_id]
    cid = c.control_id
    recipe_vendors = sorted(VENDOR[v.value] for (x, v) in RECIPES if x == cid)
    w(f"## {cid}\n")
    w(f"**{c.title}**  \n*{c.question}*\n")
    meta = [f"Severity **{c.severity.value}**", f"kind `{c.kind.value}`", f"category `{c.category}`"]
    if c.optional_feature:
        meta.append(f"optional feature: {c.optional_feature} (N/A when a confirmed parser finds none)")
    w(" · ".join(meta) + "\n")
    w("| | |\n|---|---|")
    w(f"| Reads | {n['reads']} |")
    w(f"| PASS when | {n['pass_']} |")
    w(f"| FAIL when | {n['fail']} |")
    w(f"| UNKNOWN when | {n['unknown']} |")
    w(f"| Cisco IOS | {n['cisco']} |")
    w(f"| FortiGate | {n['forti']} |")
    seeds_line = ", ".join(f"{k} {v}" for k, v in sorted(seeds_for(c).items(), key=lambda kv: (-kv[1], kv[0])))
    w(f"| Generic path | {n['generic']} |")
    w(f"| Shipped seeds | {sum(seeds_for(c).values())}{': ' + seeds_line if seeds_line else ' (none)'} |")
    w(f"| Fix: Cisco IOS | {n['fix_cisco']} |")
    w(f"| Fix: FortiGate | {n['fix_forti']} |")
    w(f"| Fix: other vendors | {n['fix_generic']} |")
    w(f"| Recipes in `recipes.py` | {', '.join(recipe_vendors) or 'none'} |")
    w("")
    w("| Framework | Version | Requirement | Title |\n|---|---|---|---|")
    for m in c.mappings:
        fw = FW_NAME.get(m.framework, m.framework)
        vend = f" ({VENDOR.get(m.vendor.value, m.vendor.value)} only)" if m.vendor else ""
        w(f"| {fw}{vend} | {m.version} | {m.requirement_id} | {m.title} |")
    w("\n---\n")

w("""## Where the remaining coverage gaps are

* **IPsec proposals (CRYPTO-001)** are read by seeds only when written one algorithm per line; a list on one line is
  read by heuristics only, provisionally.
* **Measured coverage per dialect** (checks decided when the configuration states them) and why each dialect stops
  where it does: [seed-knowledge.md](seed-knowledge.md#coverage-per-dialect-measured).
* **Password storage and AAA on FortiGate** are UNKNOWN by design (the parser does not read them).
* **SNMP communities** cannot be taught, only shipped as seeds, because the line holds the secret.
* **Default account names** are seed-only because teaching does not draft value tables.

The resolution queue on the Teach page lists every undecided check per configuration and why; see
[architecture.md §10](architecture.md#10-human-in-the-loop-recognizers).
""")
(BACKEND.parent / "docs" / "detection-rules.md").write_text("\n".join(out) + "\n", encoding="utf-8")
print("docs/detection-rules.md written")
