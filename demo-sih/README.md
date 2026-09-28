# Demo configs for the SIH video

## Fix-to-100 files: a bad score, fixed, rescanned to 100 with 0 problems

Each flow was run end to end through the API (scan → fix → download the corrected file → rescan it).

| File | First scan | Fixed by | Rescan of the corrected file |
|---|---|---|---|
| `cisco_oneclick.cfg` | posture **41**, 15 problems | NetAuditAI alone: every fix needs no input | posture **100**, **0** problems, coverage 100% |
| `paloalto_ai_human.cfg` | posture **30**, 10 problems | 5 by NetAuditAI, 5 by a typed or AI-drafted command | posture **100**, **0** problems |
| `unknown_vendor.cfg` | posture **–**, 3 suspected problems | teach 3 lines, then 3 typed or AI-drafted commands | posture **100**, **0** problems |

**Cisco (`cisco_oneclick.cfg`).** Remediation → *Download corrected configuration* → upload that file. There's no SNMP
community, `admin` account, any-any rule or missing syslog/NTP/management ACL, so nothing needs a value or manual work.

**Palo Alto (`paloalto_ai_human.cfg`).** Telnet, HTTP, SSH v1, idle timeout and LLDP are fixed by NetAuditAI. For the
other five, press *Ask AI for a command*, or *Enter command manually* and type the command below:

| Problem | Command |
|---|---|
| MGMT-008 no AAA | `set shared server-profile tacplus TACACS-MGMT server TAC1 address 10.60.99.30` |
| MGMT-009 no banner | `set deviceconfig system login-banner "Authorized access only. Activity is monitored."` |
| LOG-001 no syslog | `set deviceconfig system syslog-server 10.60.99.50` |
| LOG-002 NTP unauthenticated | `set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key` |
| AUTH-002 no password length | `set mgt-config password-complexity minimum-length 12` |

*Verify candidate* → *Confirm* on each, then *Download corrected configuration* and upload it.

**Unknown vendor (`unknown_vendor.cfg`).** Invented syntax: the first scan shows 3 *suspected* problems and no score.
In **Adaptive learning**, confirm line 16 (MGMT-001), line 18 (MGMT-007) and line 20 (MGMT-006), then rescan: the problems
are now confirmed and scored (posture 0). Fix each on Remediation with:

| Problem | Command |
|---|---|
| MGMT-001 Telnet | `remote-console protocol ssh` |
| MGMT-007 SSH v1 | `secure-shell protocol-version 2` |
| MGMT-006 no idle timeout | `operator inactivity-lock 10 minutes` |

Verify → Confirm each, download the corrected configuration, upload it: 100, 0 problems. Taught knowledge is kept,
so to repeat this flow, disable those three lines first under **Adaptive learning → Learned mappings**.
