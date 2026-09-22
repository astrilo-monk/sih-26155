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
| Written by | the project, reviewed in a pull request | the administrator, on the Teach page |
| Lives in | `backend/data/seed_recognizers.json` | SQLite `learned_mappings` only |
| `source` column | `seed` | `runtime` |
| Loaded | automatically, on every database open | on every scan |
| Decisive | yes -it passes the same gates | yes |
| Can be stopped | yes, on the Knowledge page (stays stopped) | yes |

Neither one decides compliance: both produce **facts**, and deterministic controls decide. Absence of a seed
recognizer is never evidence -an unread concept stays `UNKNOWN` or `NOT_CONFIGURED`.

## Where it lives and how it is loaded

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

`{neg}` is what lets one entry read both forms of a concept: `{neg} telnet server` says Telnet is on for
`telnet server` and off for `no telnet server`, and `{neg} telnet` scoped to `services` does the same for a
bare Junos statement. It may only be a template's first token, because a *leading* negator negates the whole
statement -which is why it outranks any `enable` word later in the line (`undo telnet server enable` is off).

A `{host}` slot refuses a polarity word and a bare number rather than reading one as a destination: an
undetermined destination leaves the control undecided instead of guessing one.

### Settings stated by naming a thing

Most booleans are toggles, and a line carrying a value says nothing about them: `server 10.0.0.1` names an
NTP server and states nothing about authenticating it, so it cannot teach "NTP authenticated".

Two are different, and are listed in `PRESENCE_PREDICATES` (`app/facts/recognizers.py`): **management
source restriction** and **central AAA**. No dialect writes "source restriction: on" -it writes
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

A login banner is *not* in the list: `banner login` and `header login information` are valueless
statements that already teach by presence, while `set login-banner "…"` carries the message as several
tokens, and a template built from it would only match banners of the same word count.

## What is covered

61 recognizers over eight dialects that have **no dedicated parser** and stay generic/unconfirmed. The `vendor`
field is a label for readability, never a claim of parser support and never used to select a code path.

| Dialect | Concepts read |
|---|---|
| Juniper Junos | Telnet, HTTP management, SSH version, session idle timeout, remote syslog, NTP server, LLDP, RADIUS / TACACS+ servers, `allow-address` source restriction |
| Palo Alto PAN-OS | Telnet (service and interface profile), HTTP management (service and interface profile), SSH version, session idle timeout, remote syslog (two spellings), NTP server, `permitted-ip` on an interface management profile |
| Arista EOS | Telnet, HTTP management (both polarities), SSH version, session idle timeout, remote syslog, NTP server, NTP authentication, IP source routing, LLDP, login banner, management ACL applied under `management ssh`, permissive any-any rule |
| Huawei VRP | Telnet (`enable` and `undo`), HTTP management (`enable` and `undo`), remote syslog, NTP server, NTP authentication, session idle timeout, IP source routing |
| MikroTik RouterOS | Telnet, HTTP management (`www`), NTP server (two spellings), remote syslog |
| HPE Aruba AOS-CX | Telnet, HTTP management, NTP authentication, login banner, permissive any-any rule |
| Check Point Gaia | remote syslog, NTP server, NTP authentication, SNMP source restriction |
| Extreme Networks EXOS | remote syslog, NTP server, LLDP, login banner, permissive any-any rule |

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

* **Coverage is partial by design.** Central AAA, password storage, login banners, SNMP communities, source
  routing, permissive policies and IPsec proposals have no seed recognizer in these dialects: their syntax
  states the setting by presence alone, without a polarity word or a readable value, and a recognizer built
  on that would guess. Those controls stay `UNKNOWN` / `NOT_CONFIGURED` until an administrator teaches them.
* **Inverted switches are not seeded.** `management telnet` + `no shutdown` (Arista) means Telnet is *on*,
  so only the unambiguous `no management telnet` is seeded; the bare block header states nothing on its own.
* **A line with only one keyword cannot be seeded.** `disable telnet` (EXOS), `set telnet-server enabled
  false` (Gaia), `logging 192.0.2.20` (Aruba), `lldp enable` (Huawei) and `set source-routing disabled`
  (Gaia) each leave one word after stopwords, which is below the two-keyword gate. They are left for a human
  to teach with a scope or a wider template, rather than answered by a template that could match anything.
* **A setting stated by presence alone is seeded only where the line names the setting.** `banner login`
  (Arista), `banner motd` (Aruba), `configure banner before-login` (EXOS) and `set snmp allowed-source ...`
  (Gaia) are read: the statement being there *is* the setting, and `{neg}` reads its removal. `set
  login-banner "..."` (Gaia) is not -- it carries the message as several tokens, so a template built from it
  would only match banners of the same word count.
* **A unit nobody states is not invented.** `set ssh server session-timeout 600` (Gaia) and `configure ssh2
  inactivity-timeout 600` (EXOS) name no unit, and the products do not agree on one, so no idle-timeout
  entry is shipped for them.
* Recognizers read whole tokens, so a template cannot match part of a word -and a template matches a whole
  statement, so `ntp server 192.0.2.10 iburst` is not read by `ntp server {host}`: an optional trailing
  wildcard would let a template match lines it was never shown.
* A seed recognizer is decisive, so a wrong one is a real defect. Treat the file as production code.

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
