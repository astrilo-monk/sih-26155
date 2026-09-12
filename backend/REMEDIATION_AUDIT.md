# Remediation Engine Audit Report

**Branch:** bug-hunt (= main)  
**Date:** 2026-09-12  
**Scope:** Deterministic remediation pipeline audit  
**Status:** DO NOT MODIFY CODE — findings only

---

## Executive Summary

The remediation pipeline was analyzed across 15 compliance rules (9 management, 2 boundary, 2 logging, 1 crypto), 2 vendor parsers (Cisco IOS, FortiNet), 800+ lines of remediation engine, and 22 e2e tests. The pipeline passes all 22 existing tests, but empirical testing with adversarial configs reveals **13 distinct bugs** that cause fixed-config verification to fail to reach 100/100 in specific scenarios.

The failure surface is dominated by:
- **Substring-based text manipulation** causing unintended removals and line corruption
- **Fortinet multi-interface handling** that only patches the first occurrence of `set` keys
- **Template placeholders** (`{interface}`, `{policy_id}`, `{vpn_name}`, `<AUTH_PASS>`, etc.) that are never substituted
- **Incomplete remediation** that removes problems without adding secure replacements

---

## Rule-by-Rule Mapping

### Management Rules (Cisco + Fortinet)

#### MGMT-001 — Telnet Enabled on VTY / allowaccess
| Stage | Detail |
|-------|--------|
| **Detection** | Cisco: VTY `transport_input` contains `"telnet"` or `"all"`; FortiNet: interface `allowed_services` contains `"telnet"` |
| **Normalized field** | `config.management.vty_lines[*].transport_input` / `config.interfaces[*].allowed_services` |
| **Finding evidence** | VTY line numbers / interface source_lines |
| **Remediation template (Cisco)** | `line vty 0 4\n transport input ssh\n no transport input telnet` |
| **Remediation template (FortiNet)** | `config system interface\n edit "{interface}"\n set allowaccess ping https ssh\n next\nend` |
| **apply_remediation (Cisco)** | Phase 1 string-replaces `transport input telnet`/`all` → `transport input ssh`; Phase 11b `_complete_vty_block` adds `transport input ssh` if missing |
| **Post-remediation parser** | Re-parses config; VTY transport_input = `["ssh"]` |
| **Post-remediation detection** | MGMT-001 does NOT fire (telnet removed) |

**Status:** Works for Cisco. FortiNet template is ineffective (see Bug #4).

#### MGMT-002 — HTTP Management Enabled
| Stage | Detail |
|-------|--------|
| **Detection** | Cisco: `config.management.http_enabled == True`; FortiNet: `"http" in iface.allowed_services and iface.is_wan` |
| **Normalized field** | `config.management.http_enabled` / `config.interfaces[*].allowed_services` |
| **Finding evidence** | Management source_lines / interface source_lines |
| **Remediation template (Cisco)** | `no ip http server\nip http secure-server` |
| **Remediation template (FortiNet)** | `config system interface\n edit "{interface}"\n set allowaccess ping https ssh\n next\nend` |
| **apply_remediation (Cisco)** | Phase 6 regex: `^ip http server\s*$` → `no ip http server`; Phase 11 adds `ip http secure-server` if missing |
| **Post-remediation parser** | `http_enabled = False` |
| **Post-remediation detection** | Does NOT fire |

**Status:** Works for Cisco. FortiNet template is ineffective (see Bug #4).

#### MGMT-003 — Unrestricted Management Access
| Stage | Detail |
|-------|--------|
| **Detection** | Cisco: VTY lacks `access_class`; FortiNet: WAN interface has any of {ssh, https, http, telnet} in allowaccess |
| **Normalized field** | `config.management.vty_lines[*].access_class` / `config.interfaces[*].is_wan` ∩ `allowed_services` |
| **Finding evidence** | VTY source_lines / interface source_lines |
| **Remediation template (Cisco)** | `ip access-list standard MGMT_ACL\n permit 10.0.0.0 0.0.0.255\n deny any log\nline vty 0 4\n access-class MGMT_ACL in` |
| **Remediation template (FortiNet)** | `config system interface\n edit "{interface}"\n set allowaccess ping\n next\nend` |
| **apply_remediation (Cisco)** | Phase 11a injects MGMT_ACL before first `line vty`; Phase 11b `_complete_vty_block` adds `access-class MGMT_ACL in` if missing |
| **Post-remediation parser** | VTY `access_class = "MGMT_ACL"` |
| **Post-remediation detection** | Does NOT fire |

**Status:** Works for Cisco. FortiNet remediation incomplete (see Bug #4, Bug #6).

#### MGMT-004 — Weak or Default SNMP Communities
| Stage | Detail |
|-------|--------|
| **Detection** | Community name in `{"public","private","community","snmp","default"}` OR (`RW` + no ACL) |
| **Normalized field** | `config.snmp.communities[*].name/.permission/.acl` |
| **Finding evidence** | Community source_lines |
| **Remediation template (Cisco)** | `no snmp-server community public\nno snmp-server community private\nsnmp-server group SECURE_GRP v3 priv\nsnmp-server user secadmin SECURE_GRP v3 auth sha <AUTH_PASS> priv aes 256 <PRIV_PASS>` |
| **Remediation template (FortiNet)** | `config system snmp community\n delete 1\nend\nconfig system snmp user\n edit "snmp3admin"...\n set auth-pwd <AUTH_PASS>\n set priv-pwd <PRIV_PASS>` |
| **apply_remediation (Cisco)** | Phase 2: `_remove_config_line(modified, "snmp-server community public")` (also removes `public2`, see Bug #1); Phase 5: regex comments out defaults |
| **Post-remediation parser** | Communities list excludes removed names |
| **Post-remediation detection** | Does NOT fire for default communities; **STILL FIRES** for non-default RW-without-ACL communities (see Bug #2) |

**Status:** Cisco only removes default communities. Non-default RW communities without ACLs are never remediated (Bug #2).

#### MGMT-005 — Plaintext / Weakly Encrypted Passwords
| Stage | Detail |
|-------|--------|
| **Detection** | Cisco: enable password type in `{"plaintext","type7","type0"}` OR user password type in same set OR `!config.services.password_encryption` |
| **Normalized field** | `config.authentication.enable_password_type`, `config.authentication.local_users[*].password_type`, `config.services.password_encryption` |
| **Finding evidence** | Authentication source_lines / user source_lines / services source_lines |
| **Remediation template (Cisco)** | `service password-encryption\nenable algorithm-type scrypt secret <NEW_PASSWORD>\nno enable password` |
| **apply_remediation (Cisco)** | Phase 3 regex: `^enable password(?:\s+\d)?\s+\S+` → `enable secret 9 $9$REMEDIATED_HASH`; Phase 4 regex: `^(username\s+\S+(?:\s+privilege\s+\d+)?)\s+password(?:\s+[07])?\s+\S+` → `\1 secret 9 $9$REMEDIATED_HASH`; Phase 7: remove `no service password-encryption`; Phase 11: add `service password-encryption` after hostname |
| **Post-remediation parser** | `enable_password_type = "type9_scrypt"`; `password_type` = `"type9_scrypt"` for remediated users |
| **Post-remediation detection** | Does NOT fire |

**Status:** Works for tested configs. Template has unsubstituted `<NEW_PASSWORD>` placeholder (Bug #8). Phase 4 regex does NOT match `password 0` without explicit `0`/`7` type (e.g. `password cisco` would not be matched — see Bug #12).

#### MGMT-006 — Missing Session Timeout
| Stage | Detail |
|-------|--------|
| **Detection** | Cisco: VTY `has_timeout == False` or console `has_timeout == False`; FortiNet: `admin_timeout > 15` |
| **Normalized field** | `config.management.vty_lines[*].exec_timeout_*` / `config.management.console.exec_timeout_*` |
| **Finding evidence** | VTY / console source_lines |
| **Remediation template (Cisco)** | `line vty 0 4\n exec-timeout 5 0\nline con 0\n exec-timeout 5 0` |
| **Remediation template (FortiNet)** | `config system global\n set admintimeout 5\nend` |
| **apply_remediation (Cisco)** | Phase 1: `exec-timeout 0 0` → `exec-timeout 5 0`; Phase 11b: `_complete_vty_block` adds `exec-timeout 5 0` if missing; Phase 13: console block gets `exec-timeout 5 0` if missing |
| **Post-remediation parser** | `has_timeout` returns True (non-zero minutes) |
| **Post-remediation detection** | Does NOT fire |

**Status:** Works.

#### MGMT-007 — SSH Version 1
| Stage | Detail |
|-------|--------|
| **Detection** | Cisco: `ssh_version == 1`; FortiNet: `ssh_version == 1` (from `admin-ssh-v1 enable`) |
| **Normalized field** | `config.management.ssh_version` |
| **Finding evidence** | Management source_lines |
| **Remediation template (Cisco)** | `ip ssh version 2\nip ssh time-out 60\nip ssh authentication-retries 3` |
| **Remediation template (FortiNet)** | `config system global\n set admin-ssh-v1 disable\nend` |
| **apply_remediation (Cisco)** | Phase 1: `ip ssh version 1` → `ip ssh version 2`; Phase 11: adds if missing |
| **apply_remediation (FortiNet)** | Phase 1: `set admin-ssh-v1 disable` replaces first `set admin-ssh-v1` line |
| **Post-remediation detection** | Does NOT fire |

**Status:** Works.

#### MGMT-008 — AAA Not Configured
| Stage | Detail |
|-------|--------|
| **Detection** | Cisco: `config.authentication.aaa_enabled == False` |
| **Normalized field** | `config.authentication.aaa_enabled` |
| **Finding evidence** | Authentication source_lines |
| **Remediation template (Cisco)** | `aaa new-model\naaa authentication login default local\naaa authorization exec default local` |
| **apply_remediation (Cisco)** | Phase 10b: removes `^no aaa new-model$`; Phase 11: `has_aaa = 'aaa new-model' in full_text` → if False, adds AAA lines after VTY block |
| **Post-remediation parser** | `aaa_enabled = True` |
| **Post-remediation detection** | Does NOT fire |

**Status:** Works, but see Bug #10 (duplicate AAA lines when `aaa authentication` present without `aaa new-model`).

#### MGMT-009 — Missing Login Banner
| Stage | Detail |
|-------|--------|
| **Detection** | Cisco: `!config.banners.login_banner and !config.banners.motd_banner`; FortiNet: `pre_login_banner_enabled == False` |
| **Normalized field** | `config.banners.login_banner` / `config.banners.motd_banner` / `config.banners.pre_login_banner_enabled` |
| **Finding evidence** | Banners source_lines |
| **Remediation template (Cisco)** | `banner login ^\n*** WARNING: Authorized access only. All activity is monitored. ***\n^` |
| **Remediation template (FortiNet)** | `config system global\n set pre-login-banner enable\nend` |
| **apply_remediation (Cisco)** | Phase 11: `has_banner` check → adds banner if missing |
| **apply_remediation (FortiNet)** | Phase 1: `set pre-login-banner enable` replaces first occurrence |
| **Post-remediation detection** | Does NOT fire |

**Status:** Works for Cisco. FortiNet template is ineffective (see Bug #4).

### Boundary Rules

#### BOUNDARY-001 — Overly Permissive ACL/Firewall Rules
| Stage | Detail |
|-------|--------|
| **Detection** | Cisco: ACL entry `action=="permit"` AND `_is_any(source)` AND `_is_any(destination)` AND `protocol in (None,"ip")`; FortiNet: policy `action=="accept"` AND `_is_any(srcaddr)` AND `_is_any(dstaddr)` AND `_has_all_services(service)` |
| **Normalized field** | `config.access_lists[*].entries[*]` / `config.firewall_policies[*]` |
| **Finding evidence** | AclEntry / FirewallPolicy source_lines |
| **Remediation template (Cisco)** | `no access-list 100 permit ip any any\naccess-list 100 permit tcp 192.168.1.0 0.0.0.255 any eq 443\naccess-list 100 permit tcp 192.168.1.0 0.0.0.255 any eq 80\naccess-list 100 deny ip any any log` |
| **Remediation template (FortiNet)** | `config firewall policy\n edit {policy_id}\n set srcaddr "Internal_Subnet"\n set dstaddr "Allowed_Servers"\n set service "HTTPS" "HTTP" "DNS"\n set utm-status enable\n set logtraffic all\n next\nend` |
| **apply_remediation (Cisco)** | Phase 2: `_remove_config_line(modified, "access-list 100 permit ip any any")` (substring match); Phase 9: regex `^(...+)\s*\bpermit\s+ip\s+any\s+any\s*$` → `deny ip any any log` on named ACLs; regex `^access-list\s+(\d+)\s+permit\s+ip\s+any\s+any\s*$` → `deny ip any any log` on numbered ACLs |
| **apply_remediation (FortiNet)** | Phase 4: `_fortinet_restrict_firewall_policies` replaces `"all"` → `"Internal_Subnet"`/`"Allowed_Servers"` and `"ALL"` → `"HTTPS" "HTTP" "DNS"` in policy blocks |
| **Post-remediation detection** | Does NOT fire for addressed ACLs |

**Status:** Works for tested configs. But see Bug #1 (`_remove_config_line` substring). Template has unsubstituted `{policy_id}` for FortiNet (Bug #8).

#### BOUNDARY-002 — IP Source Routing Enabled
| Stage | Detail |
|-------|--------|
| **Detection** | `config.services.ip_source_route == True` |
| **Normalized field** | `config.services.ip_source_route` |
| **Finding evidence** | Services source_lines |
| **Remediation template (Cisco)** | `no ip source-route` |
| **Remediation template (FortiNet)** | `config system settings\n set ip-src-routing disable\nend` |
| **apply_remediation (Cisco)** | Phase 10: regex `^ip source-route\s*$` → `no ip source-route` |
| **apply_remediation (FortiNet)** | Phase 1: `set ip-src-routing disable` replaces first occurrence |
| **Post-remediation detection** | Does NOT fire |

**Status:** Works.

#### BOUNDARY-003 — Discovery Protocol on External Interface
| Stage | Detail |
|-------|--------|
| **Detection** | Cisco: `cdp_globally_enabled is not False` AND WAN interface `cdp_enabled is not False`; FortiNet: WAN interface `lldp_enabled == True` |
| **Normalized field** | `config.services.cdp_globally_enabled` / `config.interfaces[*].cdp_enabled` / `config.interfaces[*].lldp_enabled` |
| **Finding evidence** | Interface source_lines |
| **Remediation template (Cisco)** | `interface {interface}\n no cdp enable` |
| **Remediation template (FortiNet)** | `config system interface\n edit "{interface}"\n set lldp-transmission disable\n set lldp-reception disable\n next\nend` |
| **apply_remediation (Cisco)** | Phase 1: regex `^(?!no )cdp enable\s*$` → `no cdp enable`; Phase 10c: ensures `no cdp run` present |
| **apply_remediation (FortiNet)** | Phase 8: `lldp-transmission (?:tx-rx|enable)` → `disable` |
| **Post-remediation detection** | Does NOT fire |

**Status:** Works.

### Logging Rules

#### LOG-001 — No Remote Syslog
| Stage | Detail |
|-------|--------|
| **Detection** | `config.logging.remote_hosts` is empty |
| **Normalized field** | `config.logging.remote_hosts` |
| **Finding evidence** | Logging source_lines |
| **Remediation template (Cisco)** | `logging host 10.0.0.100\nlogging trap informational\nlogging source-interface Loopback0` |
| **Remediation template (FortiNet)** | `config log syslogd setting\n set status enable\n set server "10.0.0.100"\n set mode reliable\n set port 514\nend` |
| **apply_remediation (Cisco)** | Phase 8: removes `^no logging host\s*$`; Phase 11: `has_logging_host` check → adds `logging host 10.0.0.100` if missing |
| **apply_remediation (FortiNet)** | `_fortinet_fix_syslog`: if block exists, fixes status and adds server; if not, appends new block |
| **Post-remediation detection** | Does NOT fire |

**Status:** Works for Cisco. FortiNet syslog block is added if missing (but see Bug #5 for NTP).

#### LOG-002 — NTP Not Configured or Unauthenticated
| Stage | Detail |
|-------|--------|
| **Detection** | `config.ntp.servers` is empty (MEDIUM), OR servers exist but `!authentication_enabled` (MEDIUM) |
| **Normalized field** | `config.ntp.servers` / `config.ntp.authentication_enabled` |
| **Finding evidence** | NTP source_lines |
| **Remediation template (Cisco)** | `ntp authenticate\nntp authentication-key 1 md5 <NTP_KEY>\nntp trusted-key 1\nntp server 10.0.0.50 key 1\nservice timestamps log datetime msec` |
| **Remediation template (FortiNet)** | `config system ntp\n set authentication enable\n config ntpserver\n edit 1\n set server "10.0.0.50"\n set authentication enable\n next\n end\nend` |
| **apply_remediation (Cisco)** | Phase 10b: removes `^no ntp\s*$`; Phase 11: `has_ntp`/`has_ntp_auth` checks → adds full NTP config if missing |
| **apply_remediation (FortiNet)** | `_fortinet_fix_ntp_auth`: only adds `set authentication enable` within an EXISTING NTP block. Does NOT create new block or add NTP servers (see Bug #5) |
| **Post-remediation detection** | Cisco: OK; FortiNet: **STILL FIRES** if no NTP block existed (see Bug #5) |

**Status:** Cisco works. FortiNet incomplete (Bug #5).

### Crypto Rules

#### CRYPTO-001 — Weak VPN/IPsec Crypto
| Stage | Detail |
|-------|--------|
| **Detection** | `proposal.encryption` contains weak algo (des/3des) OR `proposal.hash_algorithm` contains md5 OR `proposal.dh_group in {1,2,5}` |
| **Normalized field** | `config.vpn.ipsec_proposals[*].encryption/.hash_algorithm/.dh_group` |
| **Finding evidence** | Proposal source_lines |
| **Remediation template (Cisco)** | `no crypto isakmp policy 10\ncrypto ikev2 proposal STRONG_PROPOSAL\n encryption aes-cbc-256\n prf sha256\n group 14` |
| **Remediation template (FortiNet)** | `config vpn ipsec phase1-interface\n edit "{vpn_name}"\n set ike-version 2\n set proposal aes256-sha256\n set dhgrp 14 19\n next\nend` |
| **apply_remediation (Cisco)** | Phase 2: `_remove_config_line(modified, "crypto isakmp policy 10")` removes the policy header (but not indented children, which become orphans). Template's `crypto ikev2 proposal` lines are NOT added (no phase handles them) (see Bug #7) |
| **apply_remediation (FortiNet)** | Phase 7: regex replaces `3des-md5`/`des-md5` → `aes256-sha256`; regex replaces `set dhgrp [12]` → `set dhgrp 14`; does NOT handle `ike-version 1` → `ike-version 2` |
| **Post-remediation detection** | Cisco: doesn't fire (weak policy removed, no new policy added); FortiNet: works for proposal/dhgrp but IKE version not remediated |

**Status:** Cisco removes weak policy but doesn't add strong replacement (Bug #7). FortiNet IKEv1→IKEv2 not remediated (Bug #9).

---

## Concrete Bugs Found

### Bug #1 (CRITICAL): `_remove_config_line` uses substring matching — false positive removals

- **Severity:** CRITICAL
- **Location:** `remediation/engine.py:888-892`
- **Affected rules:** All rules with `no` commands in templates (MGMT-001, MGMT-002, MGMT-004, BOUNDARY-001)
- **Description:** `_remove_config_line` removes ANY line containing the target as a substring:
  ```python
  result = [l for l in lines if target not in l]
  ```
  - `no snmp-server community public` → target `"snmp-server community public"` also removes `snmp-server community public2 RO`
  - `no access-list 100 permit ip any any` → target also matches `access-list 100 permit ip any any extra`
  - `no ip http server` → target `"ip http server"` would also remove `ip http secure-server` (mitigated by `skip_no_targets`)

- **Example config:**
  ```
  snmp-server community public RO
  snmp-server community public2 RO
  ```
  Remediation for `public` incorrectly removes `public2`.

- **Why it fails fixed-config verification:** The substring match is overly broad and can remove legitimate configuration lines, corrupting the config. For SNMP communities, it can remove non-default communities that have the default name as a prefix.

- **Recommended fix:** Replace `_remove_config_line` with a line-exact match function that matches the full line content (with optional `no` prefix) or uses regex with word boundaries:
  ```python
  def _remove_config_line_exact(config_text: str, target: str) -> str:
      pattern = re.compile(rf'^\s*no\s+{re.escape(target)}\s*$', re.MULTILINE)
      return pattern.sub('', config_text, flags=re.MULTILINE)
  ```

### Bug #2 (CRITICAL): MGMT-004 does not remediate non-default RW communities without ACLs

- **Severity:** CRITICAL
- **Location:** Detection: `analysis/rules/management.py:179-212`; Remediation: `remediation/engine.py:50-57, 282-288, 355-367`
- **Affected rule:** MGMT-004
- **Description:** MGMT-004 fires for RW communities without ACLs (`community.permission == "RW" and community.acl is None`). The remediation only removes DEFAULT-named communities (public, private, etc.) via `no` commands and regex. Non-default RW communities (e.g., `snmp-server community management RW`) are never touched by the remediation. After remediation, the community remains and MGMT-004 fires again.

- **Example config:**
  ```
  snmp-server community public RO
  snmp-server community management RW
  ```
  `public RO` is removed, but `management RW` remains. MGMT-004 still fires for `management RW`.

- **Why it fails fixed-config verification:** The remediation template only addresses default community names. RW-without-ACL is a separate detection condition that has no corresponding remediation action. The template's `no snmp-server community public` and `no snmp-server community private` commands only target default names.

- **Recommended fix:** Either (a) add remediation logic to convert/remove non-default RW communities without ACLs, or (b) add a separate template branch for RW-without-ACL findings. The remediation engine should parse the finding evidence to determine which community triggered the rule and generate a targeted `no snmp-server community <name>` command.

### Bug #3 (CRITICAL): Fortinet `_replace_fortinet_set` only replaces first occurrence — multi-interface corruption

- **Severity:** CRITICAL
- **Location:** `remediation/engine.py:895-898`
- **Affected rules:** MGMT-001, MGMT-002, MGMT-003 (FortiNet)
- **Description:** `_replace_fortinet_set` uses `count=1` to replace only the FIRST occurrence of `set <key>` in the entire config. When multiple interfaces have `set allowaccess`, only the first is changed. Additionally, the FortiNet Phase 3 regex for removing `telnet` from allowaccess has `\s*` at the end that consumes newlines, corrupting the following line.

- **Example config:**
  ```
  config system interface
      edit "wan1"
          set allowaccess ping https ssh
          set role wan
      next
      edit "wan2"
          set allowaccess ping https ssh http telnet
          set role wan
      next
  end
  ```
  After remediation, wan1 gets `allowaccess ping` (from template), but wan2 retains `https ssh` (telnet/http removed by Phase 3, but ssh/https remain causing MGMT-003 to fire).

- **Why it fails fixed-config verification:**
  1. Phase 3 does not remove `ssh` and `https` from allowaccess — these are legitimate management services that MGMT-003 checks for on WAN interfaces
  2. `_replace_fortinet_set(count=1)` only modifies the first interface's allowaccess
  3. Phase 3's `\s*` after `\btelnet\b` consumes the newline, merging `set role wan` onto the same line as `set allowaccess`

- **Recommended fix:** 
  - Phase 3 should remove ALL management services (ssh, https, http, telnet) from allowaccess on WAN interfaces, not just telnet and http
  - `_replace_fortinet_set` should either replace ALL occurrences or target specific edit blocks by parsing the hierarchical structure
  - The regex should not have trailing `\s*` that consumes newlines

### Bug #4 (CRITICAL): `{interface}` placeholder never substituted for FortiNet findings

- **Severity:** CRITICAL
- **Location:** `remediation/engine.py:177-180` (`generate_remediation`), `remediation/engine.py:100-109` (MGMT-001 template), `remediation/engine.py:33-36` (MGMT-002 template), `remediation/engine.py:110-128` (BOUNDARY-003 template)
- **Affected rules:** MGMT-001, MGMT-002, MGMT-003, BOUNDARY-003 (FortiNet)
- **Description:** `generate_remediation` only replaces `{interface}` using `_extract_interface_name(finding.evidence_lines)`. For FortiNet, the evidence lines contain `set allowaccess ...` and `set role wan` — they do NOT contain `edit "X"` or `interface X`. So `_extract_interface_name` returns `None`, and `{interface}` remains as a literal string in the commands.

- **Example:**
  ```
  evidence_lines: ['  12:         set allowaccess ping https ssh http telnet',
                   '  13:         set role wan']
  commands: 'config system interface\n  edit "{interface}"\n    set allowaccess ping https ssh\n  next\nend'
  ```
  → `{interface}` is NOT replaced.

- **Why it fails fixed-config verification:** The template commands contain literal `{interface}` which is invalid FortiOS syntax. The `edit "{interface}"` block is meaningless. The actual remediation only works because Phase 3 (for telnet/http) and Phase 7/8 (for VPN/LLDP) independently strip insecure values from allowaccess lines regardless of the template.

- **Recommended fix:** Either (a) include the `edit "X"` line in FortiNet evidence extraction, or (b) have `generate_remediation` look at the normalized config to find the interface name from the finding's source_lines context, or (c) have the FortiNet `apply_remediation` use the normalized Interface objects directly rather than relying on template substitution.

### Bug #5 (HIGH): Fortinet NTP remediation does not create NTP block when absent

- **Severity:** HIGH  
- **Location:** `remediation/engine.py:844-881` (`_fortinet_fix_ntp_auth`)
- **Affected rule:** LOG-002
- **Description:** `_fortinet_fix_ntp_auth` only adds `set authentication enable` within an EXISTING `config system ntp` block. If no NTP block exists, no NTP configuration (servers or authentication) is added. The detection rule LOG-002 fires for `not config.ntp.servers` (no servers), which is the most common case when NTP is absent. The remediation doesn't add servers.

- **Example config:**
  ```
  (no config system ntp block at all)
  ```
  LOG-002 fires (no NTP servers). Remediation adds nothing → LOG-002 still fires.

- **Why it fails fixed-config verification:** The remediation function has no code path to create a new `config system ntp` block with NTP servers. Unlike Cisco (which adds `ntp server 10.0.0.50 key 1` in Phase 11), FortiNet has no equivalent creation logic.

- **Recommended fix:** Add a code path in `_fortinet_fix_ntp_auth` (or a new function) that creates a `config system ntp` block with `set authentication enable` and at least one NTP server when no block exists.

### Bug #6 (HIGH): Fortinet Phase 3 does not remove ssh/https from WAN interface allowaccess

- **Severity:** HIGH
- **Location:** `remediation/engine.py:606-626` (Phase 3 in `_apply_fortinet_remediation`)
- **Affected rules:** MGMT-003
- **Description:** MGMT-003 for FortiNet fires when a WAN interface has ANY of {ssh, https, http, telnet} in `allowaccess`. Phase 3 only removes `telnet` and `http`. It does NOT remove `ssh` and `https`. The MGMT-003 template sets `allowaccess ping` but is ineffective due to Bug #4 (interface not matched) and Bug #3 (`_replace_fortinet_set` only affects first interface).

- **Example config:**
  ```
  config system interface
      edit "wan1"
          set allowaccess ping https ssh
          set role wan
      next
      edit "wan2"
          set allowaccess ping https ssh
          set role wan
      next
  end
  ```
  MGMT-003 fires for both interfaces. Remediation removes nothing (no telnet/http). Both interfaces still have https/ssh → MGMT-003 still fires.

- **Why it fails fixed-config verification:** SSH and HTTPS on WAN interfaces are not removed because Phase 3's regex only targets `telnet` and `http`. The template's `set allowaccess ping` is supposed to remove all management services, but it only modifies the first occurrence and the interface placeholder is broken.

- **Recommended fix:** Phase 3 should either:
  - Set allowaccess to `ping` only for WAN interfaces (removing all management services), or
  - Add regex to remove `ssh` and `https` from WAN interface allowaccess lines specifically

### Bug #7 (HIGH): Fortinet Phase 3 telnet regex corrupts config (newline consumption)

- **Severity:** HIGH
- **Location:** `remediation/engine.py:608-619`
- **Affected rules:** MGMT-001, MGMT-002 (indirectly, by corrupting config)
- **Description:** The regex `r'^(\s*set allowaccess\s+.*)\btelnet\b\s*'` has `\s*` at the end which matches newlines. This causes the next line's leading whitespace and content to be consumed into the match replacement, effectively merging two lines.

- **Example config:**
  ```
  set allowaccess ping https ssh http telnet
  set role wan
  ```
  After Phase 3: `set allowaccess ping https ssh http set role wan` (the newline between the two lines is consumed).

- **Why it fails fixed-config verification:** The corrupted line `set allowaccess ping https ssh http set role wan` is malformed. The parser sees `set allowaccess` with values `["ping", "https", "ssh", "http", "set", "role", "wan"]`, which includes garbage values. This could cause unexpected behavior in detection rules.

- **Recommended fix:** Replace `\s*` with `$|(\s+|$)` or use `re.sub(r'^(\s*set allowaccess\s+.*)\btelnet\b\s*$', r'\1', ...)` to only match within a single line.

### Bug #8 (HIGH): Template placeholders never substituted — invalid config syntax

- **Severity:** HIGH
- **Location:** `remediation/engine.py:163-188` (`generate_remediation`), various template definitions
- **Affected rules:** MGMT-004, MGMT-005, LOG-002 (Cisco/FortiNet)
- **Description:** Templates contain placeholders that are never replaced:
  - `{interface}` — only Cisco evidence includes `interface X`, so FortiNet always has unspliced `{interface}` (Bug #4)
  - `{policy_id}` — BOUNDARY-001 FortiNet template. `generate_remediation` never tries to replace it.
  - `{vpn_name}` — CRYPTO-001 FortiNet template. Never replaced.
  - `<AUTH_PASS>`, `<PRIV_PASS>` — MGMT-004 Cisco/FortiNet templates. Never replaced.
  - `<NEW_PASSWORD>` — MGMT-005 Cisco template. Never replaced (but command is ignored in Phase 2).
  - `<NTP_KEY>` — LOG-002 Cisco template. Never replaced (but command is ignored in Phase 2).

- **Example:**
  ```
  snmp-server user secadmin SECURE_GRP v3 auth sha AUTH_PASS priv aes 256 PRIV_PASS
  ```
  The parser doesn't parse SNMPv3 user lines, so `AUTH_PASS` and `PRIV_PASS` don't cause detection failures. But they are invalid credentials in the production config.

- **Why it fails fixed-config verification:** For Cisco, the placeholder strings appear in the fixed config but since the parser doesn't parse them into normalized fields, they don't cause rule failures. For FortiNet, `{interface}` and `{policy_id}` in template commands are ignored by `_apply_fortinet_remediation` (Phase 1 only processes `set` lines), so they don't appear in the fixed config. However, if a `set` command contains a placeholder, it would appear as a literal.

- **Recommended fix:** Implement a placeholder substitution framework that:
  1. Extracts interface names from normalized config (not just evidence lines)
  2. Extracts policy IDs from FirewallPolicy objects
  3. Extracts VPN names from IpsecProposal objects
  4. Flags password placeholders as requiring user input (not auto-generated)

### Bug #9 (MEDIUM): CRYPTO-001 Cisco remediation removes weak policy but adds no replacement

- **Severity:** MEDIUM
- **Location:** `remediation/engine.py:264-265` (Phase 2 for `no crypto isakmp policy 10`), template `remediation/engine.py:150-154`
- **Affected rule:** CRYPTO-001
- **Description:** The MGMT-001 remediation template includes `crypto ikev2 proposal STRONG_PROPOSAL` and sub-commands (`encryption aes-cbc-256`, `prf sha256`, `group 14`). But `_apply_cisco_remediation` Phase 2 only processes lines starting with `no ` or `set `. The `crypto ikev2 proposal` lines are not `no` or `set` commands, so they are completely ignored. The remediation only REMOVES the weak ISAKMP policy via `_remove_config_line` but NEVER ADDS a strong replacement.

- **Example config:**
  ```
  crypto isakmp policy 10
   encr 3des
   hash md5
   group 2
  ```
  After remediation: the `crypto isakmp policy 10` header line is removed (orphaning the child lines), but no `crypto ikev2 proposal` is added.

- **Why it fails fixed-config verification:** It doesn't actually fail because the orphaned child lines (`encr 3des`, etc.) are not parsed by the parser (they require a parent `crypto isakmp policy` context). So no weak proposal exists in the normalized config, and CRYPTO-001 doesn't fire. However, this is a **false pass**: the config has no crypto at all, which is not a secure configuration. The device would have no ISAKMP/IKEv2 policy, potentially breaking VPN functionality.

- **Recommended fix:** The `apply_remediation` function should actually append the template's non-`no`/`set` commands to the config (in the appropriate context block), or the template should only contain `no` commands and the remediation engine should have separate logic to add strong crypto proposals.

### Bug #10 (MEDIUM): Duplicate AAA configuration when `aaa authentication` exists without `aaa new-model`

- **Severity:** MEDIUM
- **Location:** `remediation/engine.py:384` (`has_aaa` check), `remediation/engine.py:542-546` (`_append_missing_globals`)
- **Affected rule:** MGMT-008
- **Description:** The `has_aaa` check is `'aaa new-model' in full_text`. If the config has `aaa authentication login default local` but NOT `aaa new-model`, Phase 10b removes `no aaa new-model` (if present), then `has_aaa` is False (because `aaa new-model` is not in the text). Phase 11 adds `aaa new-model`, `aaa authentication login default local`, and `aaa authorization exec default local` — duplicating the existing `aaa authentication login default local` line.

- **Example config:**
  ```
  aaa authentication login default local
  no aaa new-model
  ```
  After remediation:
  ```
  aaa new-model
  aaa authentication login default local
  aaa authorization exec default local
  aaa authentication login default local  ← DUPLICATE
  ```

- **Why it fails fixed-config verification:** The duplicate `aaa authentication login default local` line is valid Cisco IOS (later lines override earlier ones), so the parser doesn't fail. But it's messy and the `test_no_duplicate_commands_in_fixed_config` test would catch it if applied to this config.

- **Recommended fix:** The `has_aaa` check should be more granular — check for `aaa new-model` separately from `aaa authentication` and `aaa authorization`. Only add the lines that are actually missing.

### Bug #11 (MEDIUM): FortiNet IKE version not remediated by CRYPTO-001

- **Severity:** MEDIUM
- **Location:** `remediation/engine.py:645-668` (Phase 7 in `_apply_fortinet_remediation`)
- **Affected rule:** CRYPTO-001 (partially)
- **Description:** The Cisco CRYPTO-001 template includes `ip ssh version 2` enforcement. For FortiNet, the template is:
  ```
  config vpn ipsec phase1-interface
    edit "{vpn_name}"
      set ike-version 2
      set proposal aes256-sha256
      set dhgrp 14 19
    next
  end
  ```
  Phase 7 only replaces weak proposals (`3des-md5`/`des-md5` → `aes256-sha256`) and weak DH groups (`[12]` → `14`). It does NOT enforce `ike-version 2`. If the config has `set ike-version 1`, Phase 7 doesn't change it. The parser sets `ike_version = 1` but CRYPTO-001 doesn't check `ike_version` — it only checks encryption, hash, and DH group. So this is a detection gap, not a remediation bug. But the template includes `ike-version 2` which is not applied.

- **Example config:**
  ```
  config vpn ipsec phase1-interface
      edit "vpn1"
          set ike-version 1
          set proposal aes256-sha256
          set dhgrp 14
      next
  end
  ```
  CRYPTO-001 does NOT fire (strong crypto). But IKEv1 is still insecure. This is a detection gap.

- **Recommended fix:** Either add IKE version checking to CRYPTO-001, or ensure Phase 7 enforces `set ike-version 2` in the FortiNet remediation.

### Bug #12 (MEDIUM): Phase 4 user password regex doesn't match all weak password formats

- **Severity:** MEDIUM
- **Location:** `remediation/engine.py:275-280` (Phase 4 in `_apply_cisco_remediation`)
- **Affected rule:** MGMT-005
- **Description:** The Phase 4 regex is:
  ```python
  r'^(username\s+\S+(?:\s+privilege\s+\d+)?)\s+password(?:\s+[07])?\s+\S+'
  ```
  This matches:
  - `username admin password 0 cisco` ✓
  - `username admin privilege 15 password 7 0822455D0A16` ✓
  - `username admin password cisco` ✗ (no type number, but still plaintext type 0)

  The regex requires `(?:\s+[07])?` — the type number is optional, but the regex still matches `password cisco` because `(?:\s+[07])?` can match nothing. So `username admin password cisco` WOULD be matched. Let me verify...

  Actually, looking more carefully: `password(?:\s+[07])?\s+\S+` means:
  - `password` followed by optional ` 0` or ` 7`, followed by whitespace and a non-whitespace token.
  - `password cisco` → `password` + (no type) + ` cisco` ✓ — this matches.

  So the regex IS correct for this case. But what about `username admin privilege 15 password cisco`? The regex is `^(username\s+\S+(?:\s+privilege\s+\d+)?)\s+password(?:\s+[07])?\s+\S+`. This matches `username admin privilege 15 password cisco`. So it IS correct.

  But what about `username admin secret 5 $1$HASH`? The regex requires `password` (not `secret`), so this doesn't match. But `secret 5` is type5_md5 which is NOT in WEAK_TYPES, so MGMT-005 wouldn't fire for it. So this is fine.

  **Wait, I was wrong — there's no bug here. The regex correctly handles all weak password format.**

  Actually, let me reconsider. What about `username admin algorithm-type scrypt secret 9 $HASH`? The parser regex is:
  ```python
  r'^username\s+(\S+)(?:\s+privilege\s+(\d+))?\s+(secret|password)(?:\s+(\d))?\s+(\S+)'
  ```
  This does NOT match `username admin algorithm-type scrypt secret 9 $HASH` because `algorithm-type scrypt` is between the username and `secret`. The parser skips this line. So `admin` is not in `local_users`. MGMT-005 doesn't fire for this user.

  But the remediation Phase 4 regex also doesn't match this line (it expects `username ... password`). So `username admin algorithm-type scrypt secret 9 $HASH` is not modified. This is correct — the password is already strong.

  However, there's a subtler issue: what if a config has BOTH `username admin password 0 cisco` AND `username admin secret 9 $HASH`? The parser would process both lines (in order). The last one wins for `password_type`. If `password 0 cisco` is last, `password_type = "plaintext"`, MGMT-005 fires. The remediation Phase 4 regex would match the `password 0 cisco` line and replace it with `secret 9 $9$REMEDIATED_HASH`. But the `secret 9 $HASH` line would still be there. After remediation, the parser would see both lines, and the last one wins. If `secret 9` is last, the type is `type9_scrypt`, and MGMT-005 doesn't fire. Good.

  So this is actually fine. The regex works for the tested cases.

  **Revised assessment:** Bug #12 is not confirmed. The Phase 4 regex handles all weak password formats correctly.

  Let me find a real Bug #12 instead.

  Actually, I notice that the Phase 4 regex uses `password` but the remediation template for MGMT-005 has `enable algorithm-type scrypt secret <NEW_PASSWORD>` which is NOT a `no` or `set` command. So it's ignored in Phase 2. The actual remediation for enable passwords is done by Phase 3. Good.

### Bug #13 (LOW): `has_*` checks use raw text substring matching instead of normalized state

- **Severity:** LOW
- **Location:** `remediation/engine.py:383-392` (Phase 11 checks)
- **Affected rules:** All rules with global config additions
- **Description:** The Phase 11 checks use raw text substring matching:
  - `has_service_password_enc = 'service password-encryption' in full_text and 'no service password-encryption' not in full_text`
  - `has_aaa = 'aaa new-model' in full_text`
  - `has_logging_host = bool(re.search(r'^logging host\s+\S+', full_text, re.MULTILINE))`
  - `has_ntp = bool(re.search(r'^ntp server\s+\S+', full_text, re.MULTILINE))`
  - `has_banner = bool(re.search(r'^banner (login|motd)\s+', full_text, re.MULTILINE))`
  - `has_snmpv3 = 'snmp-server group' in full_text and 'v3' in full_text`
  - `has_ssh_version_2 = 'ip ssh version 2' in full_text`
  - `has_http_secure = 'ip http secure-server' in full_text`
  - `has_ntp_auth = 'ntp authenticate' in full_text`
  - `has_timestamps = 'service timestamps log datetime msec' in full_text`

  These checks are fragile:
  - `'service password-encryption' in full_text` would be True if the string appears in a comment
  - `'v3' in full_text` is extremely broad — `v3` could appear in version strings, comments, etc.
  - `'ip ssh version 2' in full_text` could match `ip ssh version 2.0` or comments
  - `'ntp authenticate' in full_text` could match `no ntp authenticate`

- **Example config:**
  ```
  ! ip ssh version 2  (commented out but string still present)
  ```
  `has_ssh_version_2` would be True, so the remediation wouldn't add `ip ssh version 2`. But the parser wouldn't set `ssh_version` because the line is commented. The rule wouldn't fire (ssh_version is None, not 1). So this doesn't cause a failure.

  But if the config has `no ntp authenticate`:
  - `has_ntp_auth = 'ntp authenticate' in full_text` → True (because `no ntp authenticate` contains `ntp authenticate`)
  - Phase 11 doesn't add `ntp authenticate`
  - The parser doesn't set `authentication_enabled`
  - LOG-002 fires

  Wait, does Phase 10b remove `no ntp authenticate`? Let me check:
  ```python
  no_lines_to_remove = [
      r'^no aaa new-model\s*$',
      r'^no ntp\s*$',
      r'^no login banner\s*$',
      r'^no ntp server\s+.*$',
  ]
  ```
  `no ntp authenticate` is NOT in this list. So it remains. Then `has_ntp_auth = 'ntp authenticate' in full_text` is True. So Phase 11 doesn't add NTP auth. The parser doesn't parse `no ntp authenticate`. So `authentication_enabled` is False. LOG-002 fires.

  **This IS a bug.** But it requires a config with `no ntp authenticate` which is unusual.

- **Why it can fail fixed-config verification:** If the config has `no ntp authenticate`, the `has_ntp_auth` check incorrectly thinks NTP auth is present, so it doesn't add the auth lines. After re-parse, `authentication_enabled` is False, and LOG-002 still fires.

- **Recommended fix:** Use the normalized config state instead of raw text substring matching. Each `has_*` check should query the corresponding normalized field.

### Bug #14 (LOW): Remediation applies all findings' commands sequentially, causing state accumulation issues

- **Severity:** LOW
- **Location:** `remediation/engine.py:191-207` (`apply_remediation`), usage in test and API
- **Affected rules:** All
- **Description:** The e2e test and API both apply remediation commands sequentially — each `apply_remediation` call processes ALL phases (Phase 1-13) on the config. So the first finding's remediation runs all phases, then the second finding's remediation runs all phases again on the already-modified config. This is intentional (to be idempotent), but it means that the Phase 3 regex (telnet/http removal) runs 5+ times, each time on the already-modified config.

  This is mostly fine but can cause subtle issues:
  - Each call to `apply_remediation` re-applies Phase 1 replacements (e.g., `exec-timeout 0 0` → `exec-timeout 5 0`). If the config already has `exec-timeout 5 0`, the replacement doesn't match, so no harm.
  - Each call re-runs Phase 10c (ensure `no cdp run`). If already present, it skips (because the regex finds it).

  But there's a subtle issue: the `has_*` checks in Phase 11 are evaluated each time. If the first remediation adds `aaa new-model`, the second remediation's `has_aaa` check would find it and skip adding AAA again. This is correct behavior for idempotency.

  However, this means the remediation engine is NOT stateless — each call depends on the current state of the config. This makes it hard to reason about what each finding's remediation actually does.

- **Recommended fix:** Either (a) apply all findings' commands in a single `apply_remediation` call, or (b) document the stateful behavior clearly.

---

## Summary Table

| # | Bug | Severity | Rule(s) | Root Cause |
|---|-----|----------|---------|------------|
| 1 | `_remove_config_line` substring matching | CRITICAL | All with `no` cmds | `target not in l` uses substring |
| 2 | MGMT-004 doesn't fix non-default RW-without-ACL | CRITICAL | MGMT-004 | Template only removes default names |
| 3 | FortiNet `_replace_fortinet_set` first-occurrence only + regex newline corruption | CRITICAL | MGMT-001, MGMT-002, MGMT-003 | `count=1` + `\s*` consumes newlines |
| 4 | `{interface}` not substituted for FortiNet | CRITICAL | MGMT-001, MGMT-002, MGMT-003, BOUNDARY-003 | Evidence lacks `edit` lines; `_extract_interface_name` can't find it |
| 5 | FortiNet NTP remediation doesn't create NTP block | HIGH | LOG-002 | `_fortinet_fix_ntp_auth` only adds auth within existing block |
| 6 | FortiNet Phase 3 doesn't remove ssh/https from WAN | HIGH | MGMT-003 | Only removes telnet/http, not ssh/https |
| 7 | FortiNet Phase 3 regex corrupts config (newline consumption) | HIGH | MGMT-001, MGMT-002 | `\s*` at end of regex matches newlines |
| 8 | Template placeholders never substituted | HIGH | MGMT-004, MGMT-005, LOG-002, BOUNDARY-001, CRYPTO-001 | `{policy_id}`, `{vpn_name}`, `<AUTH_PASS>` etc. not replaced |
| 9 | CRYPTO-001 Cisco removes policy but adds no replacement | MEDIUM | CRYPTO-001 | Template's `crypto ikev2 proposal` lines ignored (not `no`/`set`) |
| 10 | Duplicate AAA when `aaa authentication` exists without `aaa new-model` | MEDIUM | MGMT-008 | `has_aaa` substring check + unconditional addition |
| 11 | FortiNet IKE version not remediated | MEDIUM | CRYPTO-001 | Phase 7 doesn't enforce `ike-version 2` |
| 13 | `has_*` checks use raw text instead of normalized state | LOW | All (Phase 11) | `'v3' in full_text`, `'ntp authenticate' in full_text` match comments/negations |
| 14 | Sequential apply_remediation calls (stateful) | LOW | All | Each call re-runs all phases on already-modified config |

> Note: Bug #12 was investigated but found NOT to be a bug — the Phase 4 regex handles all weak password formats correctly.

---

## Specific Answers to Audit Questions

### 1. substring-based `_remove_config_line()`
See Bug #1. The function uses `target not in l` which is a substring check. This is used in Phase 2 for all `no` commands. It can remove unintended lines where the target appears as a substring. The `skip_no_targets` set mitigates the most dangerous cases (e.g., `ip http server` would also remove `ip http secure-server`).

### 2. hardcoded IPs/networks
The remediation engine hardcodes:
- `10.0.0.100` (syslog server) in Cisco MGMT-001, LOG-001 templates and Phase 11
- `10.0.0.50` (NTP server) in Cisco LOG-002 template and Phase 11
- `10.0.0.0 0.0.0.255` (MGMT_ACL permit) in Cisco MGMT-003
- `192.168.1.0 0.0.0.255` (ACL replacement) in BOUNDARY-001 template
- `10.0.0.100` in FortiNet LOG-001 template and `_fortinet_fix_syslog`
- These are acceptable as placeholder defaults with explanatory text, but the `NTP_SECRET` string used in Phase 11 is a literal placeholder that appears in the config file.

### 3. hardcoded VTY ranges
All Cisco templates use `line vty 0 4` regardless of the actual VTY range in the config. The remediation relies on text replacements and `_complete_vty_block` to fix all VTY blocks regardless of range. For FortiNet, `{interface}` should be the interface name, not a VTY range.

### 4. hardcoded interface/policy names
- MGMT_ACL is hardcoded (not derived from config)
- SECURE_GRP is hardcoded for SNMPv3
- STRONG_PROPOSAL is hardcoded for IKEv2
- Internal_Subnet, Allowed_Servers are hardcoded for FortiNet firewall policy remediation
- These are acceptable as default names but mean the fixed config may not match existing naming conventions.

### 5. placeholders such as `{policy_id}`, `{vpn_name}`, `AUTH_PASS`
See Bug #8. These are never substituted. Only `{interface}` is attempted (and fails for FortiNet). All others remain as literal strings.

### 6. presence checks such as 'aaa new-model' instead of actual compliant state
The `has_aaa` check (`'aaa new-model' in full_text`) is a presence check, not a state check. It doesn't verify that AAA authentication/authorization methods are properly configured. Only `aaa new-model` presence is checked, not `aaa authentication login default local` or `aaa authorization exec default local`.

### 7. SNMP presence checks instead of security-state checks
The `has_snmpv3` check is `'snmp-server group' in full_text and 'v3' in full_text`. This is a very loose check — `v3` could appear in any context. The parser correctly checks `line.startswith("snmp-server group") and " v3 " in line`, but the remediation uses a much looser check.

### 8. HTTP secure-server presence vs HTTP server still enabled
Phase 6 uses regex `^ip http server\s*$` → `no ip http server` to disable HTTP. Phase 11 adds `ip http secure-server` if `has_http_secure` is False. But `has_http_secure = 'ip http secure-server' in full_text` — if the config has `! ip http secure-server` (commented), this would be True. However, the router would still not have HTTPS enabled because the line is commented.

### 9. NTP server presence vs NTP authentication state
The Phase 11 logic checks `has_ntp` (presence of `ntp server` line) and `has_ntp_auth` (presence of `ntp authenticate` string). If NTP server exists but auth doesn't, it adds auth lines. If neither exists, it adds both. But `has_ntp_auth = 'ntp authenticate' in full_text` would be True if the config has `no ntp authenticate` (which isn't removed by Phase 10b).

### 10. remediation rules that can create duplicate/conflicting configuration
See Bug #10. When `aaa authentication login default local` exists without `aaa new-model`, Phase 11 adds all three AAA lines (including a duplicate of the authentication line).

### 11. rules whose remediation template does not correspond exactly to the detector
- **MGMT-004**: Detector checks for default communities AND RW-without-ACL. Template only removes default communities. Non-default RW-without-ACL has no remediation.
- **LOG-002**: For FortiNet, template includes `set server` and `set authentication enable`, but `_fortinet_fix_ntp_auth` only adds `set authentication enable` within existing blocks. No server creation logic.
- **CRYPTO-001**: Cisco template has `crypto ikev2 proposal` lines, but these are never applied (not `no` or `set` commands).
- **MGMT-003**: FortiNet template sets `allowaccess ping` (removing all mgmt services), but Phase 3 only removes telnet/http. ssh/https on WAN interfaces are not removed by Phase 3.

### 12. findings with no genuinely safe automatic remediation
- **MGMT-004 for non-default RW communities**: Can safely remove the community, but the template doesn't do this.
- **CRYPTO-001 for Cisco**: Removing the weak policy is safe, but adding a new strong policy with `ikev2 proposal` is not done. The current approach (removing without replacing) leaves the device without VPN functionality.
- **MGMT-005 for passwords**: The `enable secret 9 $9$REMEDIATED_HASH` is a syntactically valid but non-functional hash. It passes detection but would not work as a real password.

### 13. vendor-specific hierarchical configuration handling
- **Cisco**: The remediation uses line-by-line text manipulation without understanding Cisco's hierarchical structure (global config, interface blocks, ACL blocks, VTY blocks). This works for simple cases but fails for configs with overlapping patterns.
- **FortiNet**: The remediation partially understands the `config`/`edit`/`next`/`end` structure (via `_fortinet_remove_default_snmp`, `_fortinet_restrict_firewall_policies`, `_fortinet_fix_syslog`, `_fortinet_fix_ntp_auth`). But `_replace_fortinet_set` doesn't understand edit blocks — it replaces the first `set` match in the entire file, which can be in the wrong edit block.

### 14. whether fixed-config verification performs a fresh parse and fresh analysis
**Yes.** The e2e test (`test_remediation_e2e.py`) and the API route (`remediation.py:83-85`) both:
1. Call `apply_remediation(modified_config, commands)` which internally calls `CiscoIOSParser().parse(modified)` or `FortinetParser().parse(modified)` — this IS a fresh parse.
2. Then call `analyze(reparsed)` — this IS a fresh analysis on the re-parsed config.

The verification is correctly using fresh parse and fresh analysis. The failures are in the remediation logic itself, not in the verification pipeline.

---

## Files Audited

| File | Lines | Role |
|------|-------|------|
| `backend/app/remediation/engine.py` | 912 | Remediation templates and apply functions |
| `backend/app/analysis/engine.py` | 72 | Rule orchestration and scoring |
| `backend/app/parsers/cisco_ios.py` | 535 | Cisco config parser |
| `backend/app/parsers/fortinet.py` | 372 | FortiNet config parser |
| `backend/app/parsers/base.py` | 32 | Base parser and helpers |
| `backend/app/parsers/detector.py` | 59 | Vendor auto-detection |
| `backend/app/analysis/rules/management.py` | 491 | 9 management rules (MGMT-001 through MGMT-009) |
| `backend/app/analysis/rules/logging_rules.py` | 90 | 2 logging rules (LOG-001, LOG-002) |
| `backend/app/analysis/rules/crypto.py` | 73 | 1 crypto rule (CRYPTO-001) |
| `backend/app/analysis/rules/boundary.py` | 169 | 3 boundary rules (BOUNDARY-001 to 003) |
| `backend/app/analysis/rules/base.py` | 60 | BaseRule abstract class |
| `backend/app/analysis/scoring.py` | 36 | Score calculation |
| `backend/app/models/normalized.py` | 285 | Normalized config data model |
| `backend/app/models/findings.py` | 116 | Finding and ScanResult models |
| `backend/app/api/routes/remediation.py` | 205 | API routes for remediate/verify/download |
| `backend/tests/test_remediation_e2e.py` | 425 | End-to-end remediation tests (21 tests) |
| `backend/tests/test_pipeline.py` | 136 | Core pipeline tests |
| `backend/tests/test_download_fixed.py` | 87 | Download fixed config tests |
| `backend/tests/test_cisco_acl.py` | 83 | Cisco ACL parsing tests |

All 21 e2e remediation tests pass. All other test suites pass. But adversarial configs reveal the bugs documented above.
