# Shipped seed knowledge

## What it is

Seed knowledge is a set of **recognizers NetAuditAI ships with**, so a fresh deployment can already read
common security settings in unfamiliar vendor syntax before an administrator teaches anything.

A seed recognizer is an ordinary recognizer (see `architecture.md` §8): the same typed-slot template, the same
safety gates, the same decisive `confirmed` fact. The only difference is **provenance** -it was written,
reviewed and released with the product instead of confirmed on this deployment.

It is **not** training and **not** a second learning system. Nothing is inferred, generalized or written back
into the seed file at runtime. The file is version-controlled and reviewed like code.

| | Seed knowledge | Runtime learning |
|---|---|---|
| Written by | the project, reviewed in a pull request | the administrator, under Adaptive learning |
| Lives in | `backend/data/seed_recognizers.json`, copied into `learned_mappings` | `learned_mappings` only (SQLite or Postgres) |
| `source` column | `seed` | `runtime` |
| Loaded into the store | the first time a process opens the database (idempotent) | when the administrator saves it |
| Read | on every scan | on every scan |
| Decisive | yes -it passes the same gates | yes |
| Can be stopped | yes, on the Learned mappings page (stays stopped across restarts and reloads) | yes |

Neither one decides compliance: both produce **facts**, and deterministic controls decide. Absence of a seed
recognizer is never evidence -an unread concept stays `UNKNOWN` or `NOT_CONFIGURED`.

## Where it lives and how it is loaded

```mermaid
flowchart TD
    START["process opens the database<br/>db/database.py: init_db"] --> MIG["apply migrations"]
    MIG --> LOAD["facts/seed.py: load_seed_recognizers"]
    LOAD --> FILE{"seed file readable?"}
    FILE -->|"no"| WARN0["warning; scanner still runs"]
    FILE -->|"yes"| EACH["for each entry"]
    EACH --> SAME{"same template and scope<br/>already stored, active or not?"}
    SAME -->|"yes"| SKIP1["skip: a stopped seed stays stopped"]
    SAME -->|"no"| COLL{"collides with an<br/>administrator's mapping?"}
    COLL -->|"yes"| SKIP2["skip: never overwrite"]
    COLL -->|"no"| GATE{"validate_recognizer<br/>and secret check pass?"}
    GATE -->|"no"| WARN1["skip with a warning"]
    GATE -->|"yes"| SAVE["save_mapping(source = seed)"]
```

* File: `backend/data/seed_recognizers.json` (an `_README` key, then `recognizers[]`).
* Loader: `backend/app/facts/seed.py` → `load_seed_recognizers()`.
* Hook: `app/db/database.init_db()` calls it the first time a process opens a database, which means every
  entry point -API, tests, a fresh container -gets it, including when SQLite is empty.

The loader is deterministic and idempotent:

* an entry whose template **and scope** is already stored is skipped, active or not -so a second load
  changes nothing, and a seed an administrator stopped stays stopped;
* an entry colliding with a mapping confirmed on this deployment is skipped, never overwritten;
* an entry that fails `validate_recognizer` -or holds a secret -is skipped with a warning, so one bad line
  can never stop a deployment from starting;
* a store failure is logged and the scanner still runs.

Every entry goes through `MappingRepository.save_mapping`, so it passes exactly the gates a human-confirmed
recognizer passes: two keywords besides stopwords counting the scope, stated polarity or a true/false table,
a unit for durations, a template that matches its example line, and no secret in any stored text.

## Slot types

| Slot | Reads | Example |
|---|---|---|
| `{int}` | a whole number, with or without a version prefix | `protocol-version v2` |
| `{host}` | an address (IPv4 or IPv6) **or** a hostname / FQDN | `ntp server ntp1.example.com` |
| `{ip}` | an address only -kept for recognizers written before `{host}` | `logging host 192.0.2.20` |
| `{duration}` / `{duration:<unit>}` | a number, with the unit the line states or the one the template names | `idle-timeout 600` |
| `{enum:<name>}` | one word, looked up in a value table | `disable-telnet no` |
| `{polarity}` | a polarity word anywhere in the line | `telnet server enable` |
| `{neg}` | an **optional leading negator** (`no` / `unset` / `delete` / `undo`) | `no telnet server` |
| `{rest}` | any trailing options, last token only, destinations and AAA servers only (see Limitations) | `ntp server 192.0.2.10 key 1` |
| `{community:RO}` / `{community:RW}` | an SNMP community string, read at scan time and never stored; seed-only (see Limitations) | `snmp-server community <SECRET> ro` |

`{neg}` is what lets one entry read both forms of a concept: `{neg} telnet server` says Telnet is on for
`telnet server` and off for `no telnet server`, and `{neg} telnet` scoped to `services` does the same for a
bare Junos statement. It may only be a template's first token, because a *leading* negator negates the whole
statement -which is why it outranks any `enable` word later in the line (`undo telnet server enable` is off).

A `{host}` slot refuses a polarity word and a bare number rather than reading one as a destination: an
undetermined destination leaves the control undecided instead of guessing one.

### Settings stated by naming a thing

Most booleans are toggles, and a line carrying a value says nothing about them: `server 10.0.0.1` names an
NTP server and states nothing about authenticating it, so it cannot teach "NTP authenticated".

Three are different, and are listed in `PRESENCE_PREDICATES` (`app/facts/recognizers.py`): **management
source restriction**, **central AAA** and **login banner**. No dialect writes "source restriction: on" -it writes
`permitted-ip 10.0.0.0/24`, `allow-address …` or `trusthost1 …`, and the line being there *is* the
restriction. For these, the address or name becomes `{any}` and `{neg}` reads the polarity, so one
recognizer covers every subnet:

```
taught:  set deviceconfig system permitted-ip 10.10.10.0/24
stored:  {neg} set deviceconfig system permitted-ip {any}
reads:   set deviceconfig system permitted-ip 192.0.2.0/24        -> restricted
         set deviceconfig system ntp-servers … 192.0.2.10         -> no fact
```

The list is short and deliberate: adding a predicate to it lets a line that merely mentions the setting
teach it. The rule is enforced in `validate_recognizer`, not only in the draft, so hand-writing
`{neg} ntp server {any}` for "NTP authenticated" is refused the same way.

### The line has to be about the setting

A recognizer is decisive, so the line it is built from has to be the line that answers the question.
`validate_recognizer` splits this in two:

* **The line states its own on/off.** Then the administrator names it, in any words. This is what
  teaching is for: `management-plane legacy-access disabled` may well be how a device says Telnet is
  off, and no word list will ever contain every vendor's spelling.
* **The line states nothing of its own** -it is evidence only because it is *there* -or it is read
  through a value slot, which has no polarity to anchor it. Then the line must name the concept, using
  the vocabulary in `CONCEPT_WORDS` (the same lexicon the queue suggests lines with).

Without the second rule any statement taught anything. Measured on the 49-line `sample/juniper.cfg`,
the Teach page accepted **146** nonsense combinations -`uid 2001;` teaching "management access is
restricted", `login {` teaching "stored passwords are encrypted" (a decisive PASS), `class ops;`
teaching a syslog destination of `ops`. With the rule: **2**, and both are real (`encrypted-password …`
is a password-storage line, `server …` under `ntp` is an NTP server).

The cost is the opposite error: a line that genuinely configures a setting in wording the lexicon does
not know is refused until the word is added. Extending `CONCEPT_WORDS` is the fix, and it is how the
Junos spelling `tacplus` was found -the shipped Junos TACACS+ recognizer was being rejected by its
own gate.

A login banner joined the list with the second `teach/` pass: `set login-banner "…"`, `message "…"` and
`header login information "…"` carry the message, and the message being there *is* the banner. `{any}`
reads a quoted string as one value however many words it holds, so one template covers every banner.

### One word, when the word is the feature

The two-keyword gate has one narrow exception (`_one_word_feature`): `disable telnet`, `lldp enable`,
`set lldp enabled false`, `set source-routing disabled` and `logging 192.0.2.20` are whole statements
about one feature. One keyword is enough when nothing else varies (no `{any}`) and either the switch is
spelled out in words, the word is a feature compound (`source-routing`, `telnet-server`), or an `{ip}`
slot follows a word that names the concept. `set telnet {polarity}` is none of these -inside a block it
may be a client or per-interface setting- and is still refused.

### Password storage without a password

A password-storage line always holds the secret, so its template puts slots there:
`username {any} privilege {any} secret {enum:type} {any}`. The store refuses any text that redaction
would change *unless* everything redaction removes is a slot or an existing `<SECRET:…>` placeholder
(`_holds_secret` in `app/db/mappings.py`), so the type is read and no value is ever stored. Example lines
use the placeholder: `secret 0 <SECRET:type0>`. The cited line does hold a secret, exactly as a vendor
parser's password fact does; every path to the AI redacts evidence first.

## What is covered

274 recognizers under 24 `vendor` labels: **16 device dialects** with no dedicated parser (Junos, PAN-OS, Arista EOS,
Huawei VRP, MikroTik RouterOS, Check Point Gaia, Extreme EXOS, HPE Aruba AOS-CX, Cisco NX-OS, ASA, IOS-XR, SONiC,
Cumulus NVUE, Dell OS10, VyOS, Fortinet FortiSwitchOS), two shared labels (Arista and NX-OS; Junos and VyOS, whose
`set system syslog host` and `set system ntp server` spellings are identical), three cloud exports (AWS security groups, Azure NSG, GCP firewall
rules) and Terraform for AWS, Azure and GCP. All of them stay generic / unconfirmed. The `vendor` field is a label for
readability, never a claim of parser support and never used to select a code path (it does name the *dialect* for
learned absence, see [architecture.md §5](architecture.md#learned-absence-on-the-generic-path)).

### Coverage matrix

How many shipped recognizers read each setting, per dialect (generated from `seed_recognizers.json`). An empty cell
means that setting is answered only by heuristics (provisional) or by teaching.

Columns: **Telnet**, **HTTP** management (MGMT-001/002) · **Src** source restriction (MGMT-003) · **Ext** external
exposure (MGMT-010) · **SSH** version (MGMT-007) · **Idle** timeout (MGMT-006) · **Cry** weak management crypto
(CRYPTO-002) · **AAA** (MGMT-008) · **Pwd** password storage (MGMT-005) · **Lock** failed-login limit (AUTH-001) ·
**Len** password length (AUTH-002) · **Acct** default account (AUTH-003) · **SNMP** community (MGMT-004/011) ·
**Syslog** (LOG-001) · **NTP** server, **NTPa** NTP authentication (LOG-002) · **Ban** banner (MGMT-009) · **SrcR**
source routing (BOUNDARY-002) · **LLDP** (BOUNDARY-003) · **Rtr** redirects / proxy-ARP / directed broadcast
(BOUNDARY-004) · **Any** any-any rule (BOUNDARY-001) · **RLog** rule logging (LOG-003).

| Dialect | Total | Telnet | HTTP | Src | Ext | SSH | Idle | Cry | AAA | Pwd | Lock | Len | Acct | SNMP | Syslog | NTP | NTPa | Ban | SrcR | LLDP | Rtr | Any | RLog |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Juniper Junos | 34 | 2 | 3 | 2 | 2 | 2 | 2 |  | 8 | 1 | 1 | 1 | 2 | 1 | 1 | 1 |  | 2 |  | 3 |  |  |  |
| Arista EOS | 27 | 1 | 2 | 1 |  | 1 | 1 |  | 1 | 2 | 2 | 1 | 2 | 4 | 2 | 1 | 2 | 1 | 1 | 1 |  | 1 |  |
| Palo Alto PAN-OS | 25 | 2 | 2 | 2 |  | 1 | 2 |  | 2 | 1 | 1 | 1 | 1 | 1 | 4 | 1 | 1 | 1 |  | 1 |  |  | 1 |
| MikroTik RouterOS | 18 | 2 | 1 |  |  |  |  | 2 |  | 4 |  |  |  | 3 | 1 | 2 |  | 1 |  | 1 |  | 1 |  |
| Huawei VRP | 17 | 2 | 2 |  |  |  | 1 |  |  | 1 |  |  | 1 | 2 | 1 | 1 | 1 | 1 | 1 | 1 |  | 2 |  |
| Terraform (AWS) | 17 |  |  | 12 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 5 |  |
| Check Point Gaia | 13 | 1 | 1 | 1 |  |  | 1 |  |  |  |  | 1 |  | 1 | 1 | 1 | 1 | 1 | 1 | 1 |  | 1 |  |
| Azure NSG (JSON) | 12 |  |  | 6 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 6 |  |
| Extreme Networks EXOS | 12 | 1 | 1 | 1 |  |  | 1 |  |  | 1 |  |  | 1 | 1 | 1 | 1 |  | 1 |  | 1 |  | 1 |  |
| Terraform (Azure) | 12 |  |  | 6 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 6 |  |
| Cisco NX-OS | 11 | 1 |  | 1 |  |  | 1 |  | 2 | 1 | 1 | 1 |  | 1 | 1 |  |  |  |  | 1 |  |  |  |
| SONiC (config_db.json) | 11 |  |  |  |  |  |  |  | 2 |  |  |  |  | 2 | 1 | 6 |  |  |  |  |  |  |  |
| HPE Aruba AOS-CX | 10 | 1 | 1 |  |  |  |  |  |  | 1 | 1 |  | 1 | 1 | 1 |  | 1 | 1 |  |  |  | 1 |  |
| Cisco ASA | 9 |  |  |  |  | 1 | 3 |  | 1 |  | 1 | 1 |  |  | 1 |  |  |  |  |  |  | 1 |  |
| GCP firewall rules (JSON) | 8 |  |  | 4 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 4 |  |
| Dell OS10 | 7 | 1 |  |  |  |  |  |  |  |  | 2 | 1 | 2 |  |  |  |  | 1 |  |  |  |  |  |
| VyOS | 7 |  |  |  |  |  |  | 2 | 1 |  |  |  | 1 | 2 |  |  |  | 1 |  |  |  |  |  |
| NVIDIA Cumulus Linux (NVUE) | 6 |  |  |  |  |  |  |  | 2 |  |  |  |  | 2 | 1 | 1 |  |  |  |  |  |  |  |
| AWS security group (JSON) | 4 |  |  | 3 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 |  |
| Arista EOS / Cisco NX-OS | 4 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 3 | 1 |  |
| Terraform (GCP) | 4 |  |  | 2 |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  | 2 |  |
| Fortinet FortiSwitchOS | 3 |  |  |  |  |  | 1 | 1 |  |  | 1 |  |  |  |  |  |  |  |  |  |  |  |  |
| Juniper Junos / VyOS | 2 |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 | 1 |  |  |  |  |  |  |  |
| Cisco IOS-XR | 1 |  |  |  |  |  |  |  |  |  |  |  |  |  | 1 |  |  |  |  |  |  |  |  |
| **All** | **274** | **14** | **13** | **41** | **2** | **5** | **13** | **5** | **19** | **12** | **10** | **7** | **11** | **21** | **18** | **16** | **6** | **11** | **3** | **10** | **3** | **33** | **1** |

CRYPTO-001 (IPsec proposals) has no column: a proposal is several values on one object, which a recognizer cannot
express.

### Concepts per dialect

References to `teach/` below mean the local corpus of configurations used while writing the seeds; it is
git-ignored and not part of the repository. Batfish test configurations (Apache-2.0) were used the same way and are
not committed either.

| Dialect | Concepts read |
|---|---|
| Juniper Junos | Brace and `set` forms (each `set` seed also reads the brace form): Telnet, HTTP management, SSH version, session idle timeout, remote syslog, NTP server, LLDP (on, or `lldp disable`), RADIUS / TACACS+ servers, `authentication-order` (one method or a bracketed list), `allow-address` and `allow-sources` source restriction, login `message` banner, `encrypted-password` storage (set form), `host-inbound-traffic system-services` on an `untrust`/`outside`/`internet` zone (MGMT-010) |
| Palo Alto PAN-OS | Telnet (service and interface profile), HTTP management (service and interface profile), SSH version, session idle timeout (two spellings), remote syslog (`log-settings syslog` server profiles, shared and per vsys, plus two `deviceconfig` spellings), NTP server, NTP authentication, `permitted-ip` (system and interface profile; `0.0.0.0/0` reads as unrestricted), login banner, `phash` password storage, LLDP per interface, TACACS+ and RADIUS server profiles, admin lockout (`set deviceconfig setting management admin-lockout failed-attempts`) |
| Arista EOS | Telnet, HTTP management (both polarities), SSH version, session idle timeout, remote syslog, NTP server, NTP authentication, IP source routing, LLDP, login banner, management ACL applied under `management ssh`, permissive any-any rule, local-only login, password storage, lockout (`aaa authentication policy lockout failure N [duration …]`), minimum password length (`password minimum length N` under `management security`), `ntp authenticate servers` |
| Huawei VRP | Telnet (`enable` and `undo`), HTTP management (`enable` and `undo`), remote syslog, NTP server, NTP authentication, session idle timeout, IP source routing, LLDP, login banner, password storage, permissive ACL rule |
| MikroTik RouterOS | Telnet (also with `port=`), HTTP management (`www`), NTP server (two spellings), remote syslog, LLDP, login note, permissive input rule, SNMP community (`/snmp community set [ find … ] name=` and `add name=`, read-only), a password written in the file (`/user set|add … password=`, either side of `group=`) |
| HPE Aruba AOS-CX | Telnet, HTTP management, NTP authentication, login banner, permissive any-any rule, remote syslog, LLDP, local-only login, password storage |
| Check Point Gaia | Telnet, HTTP management, remote syslog, NTP server, NTP authentication, SNMP source restriction, LLDP, IP source routing, session idle timeout, login banner, permissive access rule, minimum password length (`set password-controls min-password-length`) |
| Terraform (AWS) | `aws_security_group` `ingress { }`, `aws_security_group_rule` (`type = "ingress"`), `aws_vpc_security_group_ingress_rule`: SSH / Telnet / RDP from `0.0.0.0/0` or `::/0` (or restricted to a prefix: PASS), any protocol (`-1`) or every TCP port from anywhere. A rule with other attributes (`self`, `security_groups`, several CIDRs) matches no template and stays undecided |
| Terraform (Azure) | `security_rule { }` inside `azurerm_network_security_group` and `azurerm_network_security_rule`: an Inbound Allow on port 22 / 23 / 3389 or on `*` from `*`, `Internet` or `0.0.0.0/0`. Open rules only: `*` cannot fill an `{enum}` slot (it is the table's wildcard), so the source is literal and a restricted rule is not read (undecided, never PASS) |
| Terraform (GCP) | `google_compute_firewall` with `source_ranges = ["0.0.0.0/0"]` (with or without `direction = "INGRESS"`), read on its `allow { }` block: port 22 / 23 / 3389 or `protocol = "all"`. Open rules only |
| SONiC (`config_db.json`) | `SNMP_COMMUNITY` entries with `TYPE` RO / RW (a default name fails MGMT-004), `SYSLOG_SERVER` and `NTP_SERVER` entries (an NTP server with `admin_state: disabled` is not read), `TACPLUS_SERVER` / `RADIUS_SERVER` entries (central AAA). Not seeded: `AAA authentication login "tacacs+,local"` (a comma cannot fill an `{enum}` slot) and `SSH_SERVER POLICIES` (one line of a dozen optional keys). Sources: [config_db reference](https://github.com/sonic-net/sonic-buildimage/blob/master/src/sonic-yang-models/doc/Configuration.md) (NTP, syslog, TACACS+, RADIUS, AAA, SSH_SERVER), [sonic-snmp.yang](https://github.com/sonic-net/sonic-buildimage/blob/master/src/sonic-yang-models/yang-models/sonic-snmp.yang) (SNMP_COMMUNITY) |
| NVIDIA Cumulus Linux (NVUE) | `nv set service snmp-server readonly-community <string> access <any\|prefix> [view …]`, `nv set service syslog <vrf> server <host> …`, `nv set service ntp <vrf> server <host> …`, `nv set system aaa tacacs server <priority> host <ip>` and `… tacacs enable on`. The `startup.yaml` form is not read (no YAML reader ships). Sources: [SNMP](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-59/Monitoring-and-Troubleshooting/Simple-Network-Management-Protocol-SNMP/Configure-SNMP/), [syslog](https://docs.nvidia.com/networking-ethernet-software/nvue-reference/Set-and-Unset-Commands/Syslog/), [NTP](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-59/System-Configuration/Date-and-Time/Network-Time-Protocol-NTP/), [TACACS+](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-59/System-Configuration/Authentication-Authorization-and-Accounting/TACACS/) |
| Azure NSG (JSON) | `az network nsg show` (`securityRules`) and `az network nsg rule list`: an `Allow` / `Inbound` rule on port 22 / 23 / 3389 or on `*`, from `*`, `Internet` or `0.0.0.0/0`. Open rules only (as for Terraform Azure); `defaultSecurityRules` are not read. Format: [az network nsg](https://learn.microsoft.com/cli/azure/network/nsg) |
| GCP firewall rules (JSON) | `gcloud compute firewall-rules list --format=json`: an `allowed` rule, `direction: INGRESS`, `disabled: false`, from `0.0.0.0/0`, on port 22 / 23 / 3389 or `IPProtocol: all` (with or without `logConfig`, with or without one `targetTags`). A `denied` or disabled rule is not read. Format: [gcloud compute firewall-rules](https://cloud.google.com/sdk/gcloud/reference/compute/firewall-rules/list) |
| AWS security group (JSON) | any-protocol rule open to `0.0.0.0/0`, SSH / Telnet / RDP open to the world (or restricted to a prefix). The 20 checks a security group cannot express are N/A with the reason (`backend/data/platform_profiles.json`) |
| Extreme Networks EXOS | Telnet, HTTP management (`web`), remote syslog, NTP server, LLDP, login banner, permissive any-any rule, session idle timeout, password storage, SSH `access-profile` source restriction |
| Cisco NX-OS | remote syslog (`logging server`), TACACS+ server, session idle timeout under `line`, permissive any-any rule, NTP server, `username … password 0` or `5` storage, `aaa authentication login default group`, `access-class … in` under `line vty`, `feature telnet` and `feature lldp` (on or off), `userpassphrase min-length`, `ssh login-attempts` |
| Cisco ASA | remote syslog (`logging host <interface> <address>`), permissive `extended` any-any rule, NTP server, `aaa authentication <service> console <group>` (`LOCAL` alone is not central), `ssh version`, idle timeouts (`ssh timeout`, `console timeout`, `http server idle-timeout`, minutes), `aaa local authentication attempts max-fail`, `password-policy minimum-length` |
| Cisco IOS-XR | remote syslog (`logging <address> vrf …`), NTP server, TACACS+ server |
| Dell OS10 | Telnet (`ip telnet server enable`, `no …`), minimum password length and lockout (`password-attributes min-length`, `password-attributes max-retry N [lockout-period …]`), default account (`username admin password … role …`), login banner (`banner login ^C`). Syslog, NTP, NTP authentication, SNMP communities and TACACS+ are already read by the NX-OS / Arista spellings, which OS10 shares |
| VyOS | Pre-login banner (`set system login banner pre-login`), RADIUS (`set system login radius-server`), SNMP read-only community (`set service snmp community … authorization ro`), weak SSH ciphers and MACs (`set service ssh ciphers` / `macs`), the default `vyos` account. Syslog host and NTP server are shared with Junos (label `Juniper Junos / VyOS`). Quoted leaf values (`'aes256-ctr'`) are read like unquoted ones |
| Fortinet FortiSwitchOS | Under `config system global`: `admintimeout` (minutes), `admin-lockout-threshold`, `strong-crypto`. A FortiSwitch (or any FortiOS file without a FortiGate-only section) is unverified, so these are what make it decidable. The pre-login banner is deliberately not read: FortiSwitchOS takes the banner text there, FortiGate takes `enable` |

The third pass mined Batfish's multi-vendor test configurations (Apache-2.0, kept out of the repository):
servers written with trailing options (`{rest}`), NX-OS, ASA and IOS-XR spellings, and set-style Junos
(`set system tacplus-server`, `syslog host`, `ntp server`, `login class … idle-timeout`). Rejected from the
same pass: a BGP `idle-restart-timer` and an application `inactivity-timeout` read as session timeouts,
PAN-OS `from any;` read as an any-any rule on its own, a VLAN filter and a policy-routing entry read as
access rules, a PAN-OS syslog *profile* read as logs being sent, and a `key` on an NTP server read as NTP
authentication.

The second `teach/` pass read every setting the forty configurations state, where a control consumes it.
Shared spellings are one entry: `lldp enable` (Huawei, Aruba) and `aaa authentication login default local`
(Arista, Aruba). RouterOS one-line commands (`/system note set show-at-login=yes …`) are scoped to their
menu path; before this pass the tokenizer dropped them as bare headers.

One entry per concept per dialect: values, names and layout are read from slots, not memorized, so a second
address or a differently indented file needs no second entry.

Syntax examples, all of which generalize over addresses, names, numbers, indentation and block placement:

```
system { services { telnet; } }                       # Junos -Telnet reachable, "no telnet;" not
system { services { ssh { protocol-version v2; } } }  # Junos -SSH version 2
system { ntp { server 198.51.100.44; } }              # Junos -NTP server
set deviceconfig system service disable-telnet no     # PAN-OS -Telnet reachable
set deviceconfig setting management idle-timeout 30   # PAN-OS -30 minute timeout
management ssh
   idle-timeout 15                                    # Arista EOS -15 minute timeout
logging host 198.51.100.55                            # Arista EOS / IOS-like -remote syslog
telnet server enable                                  # Huawei VRP -Telnet reachable
ntp-service authentication enable                     # Huawei VRP -NTP authenticated
/ip service
set telnet disabled=yes                               # RouterOS -Telnet not reachable
no telnet server                                      # Aruba AOS-CX -off; "telnet server" is on
undo telnet server enable                             # Huawei VRP -off despite the trailing "enable"
set syslog remote logs.example.com                    # Gaia -a name, not only an address
configure syslog add 198.51.100.20 local4             # EXOS -the facility is read as {any}
set ntp server secondary 198.51.100.11                # Gaia -primary and secondary, one entry
banner login                                          # Arista -- a banner; "no banner login" is none
management ssh
   ip access-group MGMT-IN in                         # Arista -- scoped: an interface ACL is not this
ip access-list WAN-IN
   10 permit ip any any                               # Arista -- a permissive any-any rule
set network profiles interface-management-profile MGMT permitted-ip 192.0.2.0/24   # PAN-OS
system { login { profile OPS { allow-address 192.0.2.0/24; } } }                   # Junos
```

The last eleven entries were taught on the Teach page from the configurations in `teach/`, reviewed by
hand, generalized (an ACL name, a profile name, a rule number and an interface name each became `{any}`)
and then shipped here. What the same pass proposed and a person rejected is the other half of the lesson:
a `delete` / `no` line read as configuring the thing it removes, a local user read as central AAA, `set
ntp active on` read as NTP *authentication*, and a dozen templates that memorized one site's ACL or
interface names. Passing the gates makes a recognizer safe to store, not worth shipping.

## Limitations

* **Coverage is partial by design.** IPsec proposals cannot be answered by a recognizer at all, and a setting a
  dialect's files never state has nothing to read. Those controls stay `UNKNOWN` / `NOT_CONFIGURED` until an
  administrator teaches them.
* **Checks added later (MGMT-010, AUTH-001…003, CRYPTO-002, LOG-003, BOUNDARY-004)** read the same way. RouterOS
  `/ip ssh set strong-crypto=`, PAN-OS rule `log-end`, and Arista / NX-OS interface `ip redirects` / `ip proxy-arp` /
  `ip directed-broadcast` (stated only: other vendors' defaults are not assumed). Seeded: Junos `host-inbound-traffic
  system-services` on an `untrust`/`outside`/`internet` zone, `retry-options tries-before-disconnect`, `password
  minimum-length`, `login user … class`; PAN-OS `password-complexity minimum-length`, `mgt-config users …
  superuser yes`; Aruba `ssh server max-auth-attempts`, `user … group`; Arista `username … privilege`; EXOS
  `configure account`; Huawei `local-user … privilege level`. A default account is read through a value table
  of default names (`admin`, `administrator`, `root`, `cisco`, `manager`), so only those names produce a fact:
  any other name says nothing, and the account check is seed-only (teaching does not draft value tables).
* **A missing setting is decided only with a reviewed factory default.** For a dialect it understands, a
  setting no device ships with (AAA server, remote syslog, banner, NTP) that no line states is `NOT_SET`. Any other
  setting needs its vendor's factory default recorded, with its source, in `backend/data/factory_defaults.json`:
  today only PAN-OS password length (Minimum Password Complexity is off by default). A line that may state it in a
  form the seeds do not read (for length: a password line that also speaks of length or complexity) keeps it
  undecided. PAN-OS login lockout is read when the file states it (`admin-lockout failed-attempts`); its absence is
  not decided, because its factory default is not recorded in `factory_defaults.json`.
* **Discovery protocols on external interfaces.** A seeded LLDP / CDP line that names an interface is tied to it
  when a zone whose name says it is external holds that interface (`set zone untrust network layer3
  ethernet1/1`), citing both lines; on any other interface it stays undecided.
* **SNMP communities are seed-only.** The line holds the community string, so a `{community:RO}` /
  `{community:RW}` slot reads it at scan time and nothing stores it; a taught example could only be kept by
  storing the secret, so MGMT-004 cannot be taught. The access level is the template's own words, never
  guessed, and the ACL is not read: a read-write form is seeded only where the dialect writes the ACL on the
  same line, so `rw` with nothing after it really is open write access. Seeded: Junos `authorization read-only`,
  NX-OS `group network-operator`, Arista `ro` / `ro <acl>` / `ro access <acl>` / `rw`, Huawei `read` / `write`,
  PAN-OS `snmp-community-string` (PAN-OS SNMP is read-only), and read-only by the dialect's default: Check Point
  `set snmp community`, Aruba AOS-CX `snmp-server community`, EXOS `configure snmp add community` (added after
  the benchmark in `benchmark/` showed these lines only suspected). Left out: an encrypted community
  (`read cipher …`), Junos `clients …` lines, which name no access level, and EXOS `… community readonly|readwrite
  <name>`, which the secret gate refuses because the access word sits where a community string would.
* **Read from `teach/` and deliberately left out:** `ssh server timeout` (Huawei, Aruba) is the SSH login
  timeout, not an idle timeout; `/ip service set ssh address=…` (RouterOS) needs `address` as a
  source-restriction word, which would let any interface address teach it; `snmp-agent acl` (Huawei) binds
  SNMP, not management logins; `enable ssh2` (EXOS) names no version number.
* **RouterOS passwords and communities (added 2026-09-27).** `/user set|add … password=<value>` is read as a
  **plaintext** password: an export never shows a stored password, so a value in the file is the cleartext itself.
  The `{enum:storage}` slot captures the word `password` (table `{"password": "plaintext"}`) and `{any}` swallows
  the value, so neither the recognizer nor any fact holds it. A community read by
  `/snmp community … name=` fails MGMT-004 only for a default name (`public`, …). `add … write-access=yes` (RW) is
  not seeded: its options come in any order. The secret gate's one exception: a slot's argument is template
  syntax, so `name {community:RO}` is checked as `name {community}` (`app/db/mappings.py: _holds_secret`);
  every other text is checked unchanged. Redaction scopes a line by its RouterOS `/section` too
  (`app/adaptive/context.py: redaction_paths`), so a custom community name never leaves the process.
* **Read from Batfish's Junos configs and deliberately left out:** `set system ntp trusted-key N` names a key,
  and the gate will not read naming a key as "NTP is authenticated"; `set system services telnet
  connection-limit 5` does switch Telnet on in Junos, but the line states a value for another setting, so the
  gate refuses it (only the bare `set system services telnet` is seeded). The brace form of
  `encrypted-password` has no keyword of its own to anchor a template; it is read through the set-form seed,
  since every set-form seed also reads brace files (see `docs/architecture.md`, section 3). Any-any security policies
  (`… policy P match source-address any` / `then permit`) are read by the lexicon heuristics, not a seed.
* **Read from Batfish's NX-OS and ASA configs and deliberately left out:** `nxapi http port 80` states a port,
  not the switch; ASA `telnet <address> <mask> <interface>` has one keyword, below the gate's minimum; ASA
  `http <address> <mask> <interface>` opens ASDM, which is HTTPS, so it is not cleartext HTTP management. The
  Batfish Nokia SR OS configs hold no management settings to seed from.
* **Inverted switches are not seeded.** `management telnet` + `no shutdown` (Arista) means Telnet is *on*,
  so only the unambiguous `no management telnet` is seeded; the bare block header states nothing on its own.
* **A unit is the product's.** `set ssh server session-timeout` (Gaia) and `configure ssh2
  inactivity-timeout` (EXOS) name no unit and are read as seconds; PAN-OS `session-timeout` and Arista
  `idle-timeout` as minutes. A timeout whose unit is not the product's own would be misread.
* Recognizers read whole tokens, so a template cannot match part of a word -and a template matches a whole
  statement, so `ntp server 192.0.2.10 iburst` is not read by `ntp server {host}`. The one exception is
  `{rest}`, which may end a template for a **remote log destination, an NTP server or a central AAA
  server** only: `ntp server {host} {rest}` reads `ntp server 192.0.2.10 key 1 prefer`, because what
  follows a server says how to reach it, never whether it exists. A toggle cannot end in `{rest}` (a
  trailing word may be the switch), a one-keyword template cannot either, and before `{rest}` a `{host}`
  slot reads only an address or a dotted name -in `logging host inside 10.0.0.1`, `inside` is an
  interface, not a host.
* A seed recognizer is decisive, so a wrong one is a real defect. Treat the file as production code.

## Correcting a seed a deployment already holds

The loader never rewrites a stored row (that is what keeps an administrator's changes safe), so a fix to an entry
that already shipped does **not** reach an existing database through the seed file alone. It needs a migration in
`app/db/database.py`, applied to `source = 'seed'` rows only, before the loader runs. Migration v7 is the first:

* the two Huawei `http server …` seeds get a Huawei-only `dialect_fingerprint`
  (`acl-policy header info-center ntp-service snmp-agent sysname user-interface`). Cisco ASA writes the same words,
  `http server enable`, to start ASDM, which is HTTPS; before the fix an ASA file got a **decided** MGMT-002
  failure for cleartext HTTP. The fingerprint needs half of those top-level keywords to be present, which a Huawei
  VRP file meets and an ASA file does not;
* the Junos `set system syslog host` and `set system ntp server` seeds are relabelled `Juniper Junos / VyOS`, so a
  VyOS file is understood to know how it writes them.

Pinned by `tests/test_seed_expansion.py::test_existing_databases_get_the_seed_corrections_by_migration`.

## Sources for the October 2026 expansion

Every spelling added in this round comes from vendor documentation or a DISA STIG / CIS benchmark that quotes the
configuration line, never from memory:

| Seeds | Source |
|---|---|
| Cisco ASA `ssh timeout`, `console timeout`, `http server idle-timeout` | DISA Cisco ASA NDM STIG, [V-239920](https://www.stigviewer.com/stigs/cisco_asa_ndm_v2/2025-05-19/finding/V-239920) |
| Cisco ASA `password-policy minimum-length` | DISA Cisco ASA NDM STIG, [V-239914](https://www.stigviewer.com/stigs/cisco_asa_ndm_v2/2025-05-19/finding/V-239914) |
| Cisco ASA `ssh version 2`, `aaa local authentication attempts max-fail` | CIS Cisco Firewall ASA 9 benchmark ([SSH](https://guides.g5cybersecurity.com/?p=21442), [max-fail](https://guides.g5cybersecurity.com/?p=10078)) |
| Palo Alto `admin-lockout failed-attempts` (0 to 10) | [Palo Alto `set deviceconfig setting management` reference](https://docs.paloaltonetworks.com/wildfire/9-1/wildfire-admin/use-the-wildfire-appliance-cli/wildfire-appliance-configuration-mode-command-reference/set-deviceconfig-setting-management) |
| Check Point `set password-controls min-password-length` | [Gaia R81.20 Administration Guide, password policy in clish](https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_Gaia_AdminGuide/Content/Topics-GAG/Password-Policy-Gaia-Clish.htm) |
| Cisco NX-OS `userpassphrase min-length` | [CIS Cisco NX-OS benchmark 1.4.4](https://www.tenable.com/audits/items/CIS_Cisco_NX-OS_v1.2.0_L1.audit:4c52195e2e95513330d57f02546e03b2) |
| Cisco NX-OS `ssh login-attempts` | DISA Cisco NX-OS NDM STIG, [V-220480](https://www.stigviewer.com/stigs/cisco_nx_os_switch_ndm/2025-05-19/finding/V-220480) |
| Arista lockout, `password minimum length`, `ntp authenticate servers` | DISA Arista MLS EOS NDM STIG ([V-255949](https://www.stigviewer.com/stigs/arista_mls_eos_4x_ndm/2025-02-20/finding/V-255949), V-255954, V-255958) |
| Dell OS10 telnet, `password-attributes`, banner, accounts | DISA Dell OS10 Switch NDM STIG ([V-269771](https://www.stigviewer.com/stigs/dell_os10_switch_ndm/2024-12-11/finding/V-269771), [V-269781](https://www.stigviewer.com/stigs/dell_os10_switch_ndm/2024-12-11/finding/V-269781), V-269772, V-269776, V-269769) |
| VyOS banner, RADIUS, SNMP, SSH ciphers and MACs, syslog, NTP | VyOS 1.2 documentation ([login](https://docs.vyos.io/en/1.2/_sources/configuration/system/login.rst.txt), [ssh](https://docs.vyos.io/en/1.2/_sources/configuration/service/ssh.rst.txt), [snmp](https://docs.vyos.io/en/1.2/_sources/configuration/service/snmp.rst.txt), [syslog](https://docs.vyos.io/en/1.2/_sources/configuration/system/syslog.rst.txt), [ntp](https://docs.vyos.io/en/1.2/configuration/system/ntp.html)) |
| FortiSwitchOS `admintimeout`, `admin-lockout-threshold`, `strong-crypto` | [FortiSwitch `system global` attribute reference](https://ansible-galaxy-fortiswitch-docs.readthedocs.io/en/main/gen/fortiswitch_system_global.html) |

Deliberately **not** seeded in this round, and why:

* Huawei `ssh server compatible-ssh1x enable`: an SSH version is read from an `{int}` slot, and this toggle names none.
* Check Point `deny-on-fail failures-allowed`: the count only applies when `deny-on-fail enable on` is set on another
  line, so one line cannot decide it.
* Dell OS10 global `exec-timeout` (seconds): an unscoped template would also read NX-OS `line vty` timeouts (minutes).
* VyOS read-write SNMP: the restriction is written on separate `client` / `network` lines, so open write access cannot
  be told from one line.
* VyOS 1.3+ spellings (`set service ntp`, `set system login radius server … key`): not verified against the
  documentation of those releases.
* Extreme EXOS password policy: the command reference pages could not be read to confirm the syntax.

Four small engine changes came with the seeds, each with a test: the lexicon learned `userpassphrase` (NX-OS) and
`max-retry` (OS10) as setting names, `vyos` joined the default account names, the redactor no longer reads `minimum`
in `password minimum length 15` as a password (it was shown as `password <SECRET:password>`), and a typed slot may be
wrapped in one pair of quotes.

## Adding a seed recognizer safely

1. Find a real configuration line from the dialect that **states** the setting -a polarity word, a number
   with a readable unit, an address, or a bare statement inside a block that only exists when the feature is
   on. If the line only hints at the setting, stop: leave it unresolved.
2. Add an entry to `backend/data/seed_recognizers.json`:

   ```json
   {
     "concept": "NTP server",
     "vendor": "Huawei VRP",
     "predicate": "time.ntp.server",
     "command_pattern": "ntp-service unicast-server {ip}",
     "example_line": "ntp-service unicast-server 192.0.2.10"
   }
   ```

   Optional: `subject` (`telnet`, `http`, `lldp`, …), `scope_template`, `constant_value` (JSON value or enum
   table), `dialect_fingerprint`, `negatives`. Use documentation addresses (`192.0.2.0/24`,
   `198.51.100.0/24`) and never a real hostname, credential or key.
3. Generalize, do not memorize: put the value in a typed slot (`{int}`, `{host}`, `{duration[:unit]}`,
   `{enum:name}`, `{polarity}`, `{neg}`) and facilities, ids and instance names in `{any}`, and let the scope
   carry the nouns a hierarchical dialect keeps in the block header. One entry per concept per dialect -if
   you are writing a second entry that differs only in an address, a name or a number, use a slot instead.
4. Check what it must *not* match. Traffic rules, descriptions and the same leaf word in another block are
   the usual traps; a scope template is the normal fix, `negatives` the exception. A scope matches the block
   the statement is **in**, never an outer ancestor, so `server {host}` scoped to `ntp` does not answer
   `ntp { traceoptions { server … } }`.
5. Add the dialect fixture or extend one under `backend/tests/fixtures/seed_dialects/`, then run
   `python -m pytest tests/test_seed_knowledge.py` and the full backend suite. The tests already assert that
   every shipped entry validates, answers a predicate a control consumes, and holds no secret.
