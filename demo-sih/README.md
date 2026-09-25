# Demo configs for the SIH video

Two intentionally insecure configurations, 10 vulnerabilities each. Both were run through the real scan pipeline
(no AI key) and the results below are what the app actually returned.

## cisco_edge_vulnerable.cfg: Cisco ISR (dedicated parser)

The vendor is **confirmed as Cisco IOS**, and all 10 are decisive FAILs (12 findings):

| # | Vulnerability | Line(s) | Control |
|---|---|---|---|
| 1 | Telnet allowed on VTY | `transport input telnet ssh` | MGMT-001 |
| 2 | HTTP management server | `ip http server` | MGMT-002 |
| 3 | VTY open to any source (no access-class) | `line vty 0 4` | MGMT-003 |
| 4 | Default SNMP communities `public` / `private` (RW) | `snmp-server community ...` | MGMT-004 |
| 5 | Plaintext enable password, Type 7 user password | `enable password`, `password 7` | MGMT-005 |
| 6 | Idle timeout disabled | `exec-timeout 0 0` | MGMT-006 |
| 7 | SSH version 1 | `ip ssh version 1` | MGMT-007 |
| 8 | No AAA | `no aaa new-model` | MGMT-008 |
| 9 | `permit ip any any` on the WAN ACL | `ip access-list extended OUTSIDE-IN` | BOUNDARY-001 |
| 10 | IP source routing | `ip source-route` | BOUNDARY-002 |

Deliberately secure, so the report shows PASS results as well: login banner, CDP off, remote syslog,
authenticated NTP. CRYPTO-001 is N/A (no VPN). Good for showing **Remediate → rescan**.

## paloalto_fw_vulnerable.cfg: Palo Alto PAN-OS (no dedicated parser, read generically)

The vendor is **unknown**, so the file goes through the generic path. PAN-OS is read by shipped seed recognizers
(these results are **confirmed**) and by lexicon heuristics (these are **heuristic**: shown, but not scored).

| # | Vulnerability | Line(s) | App result |
|---|---|---|---|
| 1 | Telnet enabled (system + interface mgmt profile) | `disable-telnet no`, `UNTRUST-MGMT telnet yes` | **FAIL** MGMT-001 |
| 2 | HTTP management enabled | `disable-http no`, `UNTRUST-MGMT http yes` | **FAIL** MGMT-002 |
| 3 | Management open to every address | `UNTRUST-MGMT permitted-ip 0.0.0.0/0` | **FAIL** MGMT-003 |
| 4 | SNMP v2c community `public` | `snmp-community-string public` | **FAIL** MGMT-004 (heuristic) |
| 5 | Idle timeout disabled | `idle-timeout 0` | **FAIL** MGMT-006 |
| 6 | SSH protocol v1 | `ssh service protocol-version v1` | **FAIL** MGMT-007 |
| 7 | Any-to-any allow rule | `rulebase security rules Allow-All ...` (7 lines) | **FAIL** BOUNDARY-001 (heuristic) |
| 8 | NTP without authentication | `authentication-type none` | **FAIL** LOG-002 |
| 9 | DES / MD5 / DH group 1 in IKE and IPsec | `LEGACY-IKE`, `LEGACY-IPSEC` | **FAIL** CRYPTO-001 (heuristic) |
| 10 | LLDP on the internet-facing port | `ethernet1/1 layer3 lldp enable yes` | UNKNOWN BOUNDARY-003 |

#10 is UNKNOWN on purpose. The app sees LLDP switched on, but nothing in the file tells it whether `ethernet1/1`
faces the internet, so it answers "enabled, exposure undetermined" instead of guessing.

The file also has no remote syslog, no login banner and no AAA server, and uses an MD5-crypt admin hash (`phash $1$`).
The app reports the first three as NOT_CONFIGURED, and MGMT-005 as a confirmed PASS: PAN-OS keeps only a hash, which the
app treats as strong storage (as it does Cisco type 5).

**The demo story for #10:** the engine doesn't guess. An auditor would rather see "undecided, here is the line"
than a confident PASS or FAIL it can't back up. The report lists what it would need to decide.
