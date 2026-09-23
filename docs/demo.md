# Demo Script (SIH)

Uses files in the repository. Run with AI off (no Groq key) unless step 9 is shown; check the Groq quota first if it is.
Start from an empty recognizer database for a clean replay (`ADAPTIVE_DB_PATH` pointing at a new file). A new file
is not empty for long: the shipped seed recognizers load into it on first use, which is what steps 6a and 8 show.

1. **Problem.** Multi-vendor configurations are audited by hand; a tool that guesses is worse than none.
2. **Upload `backend/tests/fixtures/cisco_vulnerable.cfg`.** The **Overview** page names the device
   "Cisco IOS -read by a dedicated parser": posture 0, coverage 100%, problems by severity. Open MGMT-001 in the
   drawer (from **Findings**): cited lines, impact, NIST / CIS mappings. With AI on, *Explain this* adds a
   plain-language explanation labelled *AI-written, commentary, not evidence*.
3. **Frameworks** (sidebar, under *Intelligence*). NIST SP 800-53 Rev. 5, the DISA NDM SRG, ISO/IEC 27001:2022 Annex A and the Cisco CIS benchmark: requirement status comes from the same control
   results; point out the "not a certification" note.
4. **Remediation.** The page groups the problems into *can be fixed automatically*, *needs your input*, *needs manual action*
   and *cannot be fixed safely* (weak passwords, AAA lockout risk, any-any ACL). Enter a syslog server, NTP key ID and key, and a management subnet; regenerate. Expand a
   fixed control: cited evidence → diff → rescan checks → posture before/after. Download, then upload the downloaded
   file: vendor still confirmed, posture 72, remaining findings exactly the three human-review controls.
5. **Upload `backend/tests/fixtures/fortinet_vulnerable.cfg`.** Same controls, FortiGate facts. Its PDF report (step 13) names the model `FG100F` and firmware `7.0.5 build0304`, read from the file's `#config-version=` header. Posture 4, coverage 82%,
   *critical not assessed: MGMT-005* -the FortiGate parser does not read password storage, and the tool says so.
6. **Upload `sample/unknown.cfg`.** "Unfamiliar device -checked with generic analysis"; no vendor commands are generated. Posture "-",
   coverage 0. Provisional results: *Suspected FAIL* Telnet on lines 70–71 with evidence, never scored.
7. **Adaptive learning.** The page asks in plain language what an unfamiliar line means. Confirm line 71 for MGMT-001: drafted template `remote-console protocol {enum:protocol}`,
   gates, replay diff. Save: MGMT-001 becomes a decisive *confirmed* FAIL, coverage rises, zero AI calls.
8. **Restart the backend and upload `sample/unknown.cfg` again.** The recognizer is reused from the knowledge store (see **Adaptive learning → Learned mappings**): still decisive,
   still no AI. Upload `sample/paloalto.cfg`: still generic analysis and no invented parser, but Telnet, HTTP
   management and the syslog servers are already decisive -that is shipped seed knowledge, not learning. Open
   **Adaptive learning → Learned mappings** and switch between *Shipped* and *Taught here*.
9. **Upload `backend/tests/fixtures/seed_dialects/huawei.conf`** -a dialect nobody taught this deployment. Five
   controls are answered decisively out of the box (Telnet, HTTP management, session timeout, remote syslog, NTP),
   coverage is above 0, and every one cites a real line. The login banner stays `NOT_CONFIGURED` rather than being
   guessed. Now **teach** the SSH-version line under **Adaptive learning**: the taught recognizer and the shipped ones are used
   side by side on the rescan. See [seed-knowledge.md](seed-knowledge.md).
10. **Remediation, for the unconfirmed vendor -one click.** Press **Fix it for me**. NetAuditAI derives the change from
    the configuration itself (`delete system services telnet`, built from the file's own block path), applies it to a
    **copy**, re-reads the copy with the generic engine and shows `target`, `no_regression` and `generic_path` all
    passing -no AI, no vendor grammar, nothing taught. Then point at what it refuses: **Fix it for me** never appears
    for a check that needs a setting *added*, and it will not delete an idle timeout to make a threshold check stop
    failing. Those stay with the person who owns the command.
11. **Remediation, the other two ways.** The problem is **"Needs administrator input"**, not a dead end. Press
    *Generate candidate fix* (AI on) or *Enter command manually* and type `delete system services telnet;`. The
    candidate is labelled **AI-generated candidate · Not checked yet** and NetAuditAI has changed nothing.
    Press *Verify candidate*: it is applied to a **copy** of the uploaded file, the copy is re-read by the generic
    engine, and MGMT-001 moves **fail → not_configured** with `target`, `no_regression` and `generic_path` all
    passing. Press *Confirm*. Point out what the page says and does not say:
    * "Verified against this configuration" -the command removes the finding from the uploaded **file**;
    * it does **not** say the command is safe to run on the device, and it does not say the device was changed;
    * posture, coverage and the findings do not move: the problem is still a problem until the device is changed
      and scanned again, and *Download corrected configuration* still refuses (`409`) -NetAuditAI writes no device
      configuration for a vendor it could not confirm.
    Then press **Download verified corrected copy**. That file is the configuration you uploaded with this one
    change, exactly as it was re-analysed -the page says so: *"Verified against a copy of your uploaded
    configuration. This file has not been applied to a device."* Before verifying, that button does not exist.
12. **(Optional, AI on.)** The judge is asked only about undecided controls, with a redacted excerpt; a verified answer
    appears as "AI proposes …, awaiting confirmation" and changes neither posture nor coverage.
13. **Download the PDF report** (*Download PDF report*, on Overview). One PDF per device: device identification,
    posture and coverage, every control with the assurance behind it and the lines it cites, the framework view,
    the remediation paths, and the checks still needing input. Two things to point at: the passwords and SNMP
    community strings are redacted in the report exactly as in the browser, and the identification section states
    plainly that serial numbers and hardware inventory are not in a configuration file rather than inventing them.
14. **Close.** Architecture: parser or tokenizer → facts → controls → posture + coverage → AI only for what is
    unresolved → human confirmation → recognizer → future scans; remediation only where it can be verified.


NetAuditAI does five separable things, and only the first four:

| # | Stage | NetAuditAI |
|---|---|---|
| 1 | Detection -is there a problem, on what evidence? | yes |
| 2 | Candidate remediation -what command would change it? | yes, proposed by a person or the AI, never invented as fact |
| 3 | Verification -does that change remove the finding from this configuration? | yes, on a copy, deterministically |
| 4 | Human confirmation -does an administrator accept it? | yes, required |
| 5 | Execution on the physical device | **no** -NetAuditAI reads a device (live collection) but never writes to one |

Do not claim dedicated support for vendors other than Cisco IOS and FortiGate, AI-decided compliance, or automatic
learning without confirmation.
