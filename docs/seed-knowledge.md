# Shipped seed knowledge

## What it is

Seed knowledge is a set of **recognizers NetAuditAI ships with**, so a fresh deployment can already read
common security settings in unfamiliar vendor syntax before an administrator teaches anything.

A seed recognizer is an ordinary recognizer (see `architecture.md` §8): the same typed-slot template, the same
safety gates, the same decisive `confirmed` fact. The only difference is **provenance** — it was written,
reviewed and released with the product instead of confirmed on this deployment.

It is **not** training and **not** a second learning system. Nothing is inferred, generalized or written back
into the seed file at runtime. The file is version-controlled and reviewed like code.

| | Seed knowledge | Runtime learning |
|---|---|---|
| Written by | the project, reviewed in a pull request | the administrator, on the Teach page |
| Lives in | `backend/data/seed_recognizers.json` | SQLite `learned_mappings` only |
| `source` column | `seed` | `runtime` |
| Loaded | automatically, on every database open | on every scan |
| Decisive | yes — it passes the same gates | yes |
| Can be stopped | yes, on the Learned page (stays stopped) | yes |

Neither one decides compliance: both produce **facts**, and deterministic controls decide. Absence of a seed
recognizer is never evidence — an unread concept stays `UNKNOWN` or `NOT_CONFIGURED`.

## Where it lives and how it is loaded

* File: `backend/data/seed_recognizers.json` (an `_README` key, then `recognizers[]`).
* Loader: `backend/app/facts/seed.py` → `load_seed_recognizers()`.
* Hook: `app/db/database.init_db()` calls it the first time a process opens a database, which means every
  entry point — API, tests, a fresh container — gets it, including when SQLite is empty.

The loader is deterministic and idempotent:

* an entry whose template **and scope** is already stored is skipped, active or not — so a second load
  changes nothing, and a seed an administrator stopped stays stopped;
* an entry colliding with a mapping confirmed on this deployment is skipped, never overwritten;
* an entry that fails `validate_recognizer` — or holds a secret — is skipped with a warning, so one bad line
  can never stop a deployment from starting;
* a store failure is logged and the scanner still runs.

Every entry goes through `MappingRepository.save_mapping`, so it passes exactly the gates a human-confirmed
recognizer passes: two keywords besides stopwords counting the scope, stated polarity or a true/false table,
a unit for durations, a template that matches its example line, and no secret in any stored text.

## What is covered

23 recognizers over five dialects that have **no dedicated parser** and stay generic/unconfirmed. The `vendor`
field is a label for readability, never a claim of parser support and never used to select a code path.

| Dialect | Concepts read |
|---|---|
| Juniper Junos | Telnet, HTTP management, SSH version, session idle timeout, remote syslog, NTP server, LLDP |
| Palo Alto PAN-OS | Telnet, HTTP management, session idle timeout, remote syslog |
| Arista EOS | session idle timeout, remote syslog, NTP server |
| Huawei VRP | Telnet, HTTP management, remote syslog, NTP server, NTP authentication, session idle timeout |
| MikroTik RouterOS | Telnet, HTTP management (`www`), NTP server |

Syntax examples, all of which generalize over addresses, names, numbers, indentation and block placement:

```
system { services { telnet; } }                       # Junos — Telnet reachable
system { services { ssh { protocol-version v2; } } }  # Junos — SSH version 2
system { ntp { server 198.51.100.44; } }              # Junos — NTP server
set deviceconfig system service disable-telnet no     # PAN-OS — Telnet reachable
set deviceconfig setting management idle-timeout 30   # PAN-OS — 30 minute timeout
management ssh
   idle-timeout 15                                    # Arista EOS — 15 minute timeout
logging host 198.51.100.55                            # Arista EOS / IOS-like — remote syslog
telnet server enable                                  # Huawei VRP — Telnet reachable
ntp-service authentication enable                     # Huawei VRP — NTP authenticated
/ip service
set telnet disabled=yes                               # RouterOS — Telnet not reachable
```

## Limitations

* **Coverage is partial by design.** Central AAA, password storage, login banners, SNMP communities, source
  routing, permissive policies and IPsec proposals have no seed recognizer in these dialects: their syntax
  states the setting by presence alone, without a polarity word or a readable value, and a recognizer built
  on that would guess. Those controls stay `UNKNOWN` / `NOT_CONFIGURED` until an administrator teaches them.
* **Inverted switches are not seeded.** `management telnet` + `no shutdown` (Arista) means Telnet is *on*; a
  recognizer can only say that a line's stated polarity *is* the setting, so this is left to a human.
* Recognizers read whole tokens, so a template cannot match part of a word, and `{ip}` will not read a
  hostname — `ntp-servers primary-ntp-server ntp1.example.com` gives no fact.
* A seed recognizer is decisive, so a wrong one is a real defect. Treat the file as production code.

## Adding a seed recognizer safely

1. Find a real configuration line from the dialect that **states** the setting — a polarity word, a number
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
3. Generalize, do not memorize: put the value in a typed slot (`{int}`, `{ip}`, `{duration[:unit]}`,
   `{enum:name}`, `{polarity}`) and unrelated words in `{any}`, and let the scope carry the nouns a
   hierarchical dialect keeps in the block header.
4. Check what it must *not* match. Traffic rules, descriptions and the same leaf word in another block are
   the usual traps; a scope template is the normal fix, `negatives` the exception.
5. Add the dialect fixture or extend one under `backend/tests/fixtures/seed_dialects/`, then run
   `python -m pytest tests/test_seed_knowledge.py` and the full backend suite. The tests already assert that
   every shipped entry validates, answers a predicate a control consumes, and holds no secret.
