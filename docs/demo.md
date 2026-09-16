# Demo Script (SIH)

Uses files in the repository. Run with AI off (no Groq key) unless step 9 is shown; check the Groq quota first if it is.
Start from an empty recognizer database for a clean replay (`ADAPTIVE_DB_PATH` pointing at a new file).

1. **Problem.** Multi-vendor configurations are audited by hand; a tool that guesses is worse than none.
2. **Upload `backend/tests/fixtures/cisco_vulnerable.cfg`.** Overview → Analysis Path: vendor *cisco_ios · confirmed*,
   facts from the dedicated parser. Posture 0, coverage 100%. Open MGMT-001: cited lines, impact, NIST / CIS mappings.
3. **Frameworks.** NIST SP 800-53 Rev. 5 and the Cisco CIS benchmark: requirement status comes from the same control
   results; point out the "not a certification" note.
4. **Remediation.** The plan shows *Fixed*, *Proposed* (needs input) and *Requires human review* (weak passwords, AAA
   lockout risk, any-any ACL). Enter a syslog server, NTP key ID and key, and a management subnet; regenerate. Expand a
   fixed control: cited evidence → diff → rescan checks → posture before/after. Download, then upload the downloaded
   file: vendor still confirmed, posture 72, remaining findings exactly the three human-review controls.
5. **Upload `backend/tests/fixtures/fortinet_vulnerable.cfg`.** Same controls, FortiGate facts. Posture 4, coverage 82%,
   *critical not assessed: MGMT-005* — the FortiGate parser does not read password storage, and the tool says so.
6. **Upload `sample/unknown.cfg`.** Analysis Path: *unknown*, generic tokenizer, remediation blocked. Posture "—",
   coverage 0. Provisional results: *Suspected FAIL* Telnet on lines 70–71 with evidence, never scored.
7. **Teach.** Confirm line 71 for MGMT-001: drafted template `remote-console protocol {enum:protocol}`,
   gates, replay diff. Save: MGMT-001 becomes a decisive *confirmed* FAIL, coverage rises, zero AI calls.
8. **Restart the backend and upload `sample/unknown.cfg` again.** The recognizer is reused from SQLite: still decisive,
   still no AI. Upload `sample/paloalto.cfg`: generic analysis, provisional results, no invented parser, no remediation.
9. **(Optional, AI on.)** The judge is asked only about undecided controls, with a redacted excerpt; a verified answer
   appears as "AI proposes …, awaiting confirmation" and changes neither posture nor coverage.
10. **Close.** Architecture: parser or tokenizer → facts → controls → posture + coverage → AI only for what is
    unresolved → human confirmation → recognizer → future scans; remediation only where it can be verified.

Do not claim dedicated support for vendors other than Cisco IOS and FortiGate, AI-decided compliance, or automatic
learning without confirmation.
