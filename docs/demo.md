# Demo Script (SIH)

Uses files in the repository. Run with AI off (no Groq key) unless step 9 is shown; check the Groq quota first if it is.
Start from an empty recognizer database for a clean replay (`ADAPTIVE_DB_PATH` pointing at a new file).

1. **Problem.** Multi-vendor configurations are audited by hand; a tool that guesses is worse than none.
2. **Upload `backend/tests/fixtures/cisco_vulnerable.cfg`.** The **Results** overview names the device
   "Cisco IOS — read by a dedicated parser": posture 0, coverage 100%, problems by severity. Open MGMT-001 in the
   drawer: cited lines, impact, NIST / CIS mappings.
3. **Frameworks** (scan sub-navigation). NIST SP 800-53 Rev. 5 and the Cisco CIS benchmark: requirement status comes from the same control
   results; point out the "not a certification" note.
4. **Fix.** The page groups the problems into *can be fixed automatically*, *needs your input*, *needs manual action*
   and *cannot be fixed safely* (weak passwords, AAA lockout risk, any-any ACL). Enter a syslog server, NTP key ID and key, and a management subnet; regenerate. Expand a
   fixed control: cited evidence → diff → rescan checks → posture before/after. Download, then upload the downloaded
   file: vendor still confirmed, posture 72, remaining findings exactly the three human-review controls.
5. **Upload `backend/tests/fixtures/fortinet_vulnerable.cfg`.** Same controls, FortiGate facts. Posture 4, coverage 82%,
   *critical not assessed: MGMT-005* — the FortiGate parser does not read password storage, and the tool says so.
6. **Upload `sample/unknown.cfg`.** "Unfamiliar device — checked with generic analysis"; no vendor commands are generated. Posture "—",
   coverage 0. Provisional results: *Suspected FAIL* Telnet on lines 70–71 with evidence, never scored.
7. **Teach.** The page asks in plain language what an unfamiliar line means. Confirm line 71 for MGMT-001: drafted template `remote-console protocol {enum:protocol}`,
   gates, replay diff. Save: MGMT-001 becomes a decisive *confirmed* FAIL, coverage rises, zero AI calls.
8. **Restart the backend and upload `sample/unknown.cfg` again.** The recognizer is reused from SQLite (see **Learned**): still decisive,
   still no AI. Upload `sample/paloalto.cfg`: generic analysis, provisional results, no invented parser, no remediation.
9. **Upload `sample/juniper.cfg` and teach its `telnet;` line** (same Teach flow as step 7; the drafted template is
   `telnet` scoped to `services`). MGMT-001 becomes a decisive *confirmed* FAIL on a device whose vendor is still
   honestly `unknown`.
10. **Fix, for the unconfirmed vendor.** The problem is **"Needs administrator input"**, not a dead end. Press
    *Generate candidate fix* (AI on) or *Enter command manually* and type `delete system services telnet;`. The
    candidate is labelled **AI-generated candidate · Not checked yet** and NetAuditAI has changed nothing.
    Press *Verify candidate*: it is applied to a **copy** of the uploaded file, the copy is re-read by the generic
    engine, and MGMT-001 moves **fail → not_configured** with `target`, `no_regression` and `generic_path` all
    passing. Press *Confirm*. Point out what the page says and does not say:
    * "Verified against this configuration" — the command removes the finding from the uploaded **file**;
    * it does **not** say the command is safe to run on the device, and it does not say the device was changed;
    * posture, coverage and the findings do not move, and the download still refuses (`409`): the problem is still
      a problem until the device is changed and scanned again.
11. **(Optional, AI on.)** The judge is asked only about undecided controls, with a redacted excerpt; a verified answer
    appears as "AI proposes …, awaiting confirmation" and changes neither posture nor coverage.
12. **Close.** Architecture: parser or tokenizer → facts → controls → posture + coverage → AI only for what is
    unresolved → human confirmation → recognizer → future scans; remediation only where it can be verified.

NetAuditAI does five separable things, and only the first four:

| # | Stage | NetAuditAI |
|---|---|---|
| 1 | Detection — is there a problem, on what evidence? | yes |
| 2 | Candidate remediation — what command would change it? | yes, proposed by a person or the AI, never invented as fact |
| 3 | Verification — does that change remove the finding from this configuration? | yes, on a copy, deterministically |
| 4 | Human confirmation — does an administrator accept it? | yes, required |
| 5 | Execution on the physical device | **no** — NetAuditAI never connects to a device |

Do not claim dedicated support for vendors other than Cisco IOS and FortiGate, AI-decided compliance, or automatic
learning without confirmation.
