# Command line (CI pipelines)

Check configurations before they reach a device, the way code is checked before it is merged. Same engine as the
web app, no server.

```bash
cd backend
python -m app.cli scan ../configs/ --fail-on high --sarif netaudit.sarif
```

| Option | Meaning |
|---|---|
| `paths` | Files or directories (searched recursively; hidden files skipped). Scanned together, so checks across devices apply. |
| `--fail-on low\|medium\|high\|critical` | Exit 1 when a **decided** FAIL at or above this severity exists. Default `high`. |
| `--framework` | `NIST_800_53`, `CIS`, `DISA_STIG` or `ISO_27001` (reporting only; every check still runs). |
| `--sarif FILE` | Also write SARIF 2.1.0: each decided FAIL on the first line it cites. |
| `--json` | Print the full scan result (the same JSON as `POST /api/scan`) instead of the summary. |
| `--policy FILE` | Check against an organisation policy ([policy.md](policy.md)). |
| `--db FILE` | Use this knowledge database (with what was taught there) instead of the shipped knowledge. |

Exit codes: `0` passed, `1` a decided problem at or above the threshold, `2` bad arguments or unreadable input.

What makes it safe in a pipeline:
* **Deterministic.** AI is off whatever `.env` says, and by default a throwaway database holds only the shipped
  knowledge, so the same files always give the same result.
* **Nothing written** to the deployment's database, and nothing sent anywhere.
* **Only decided FAILs fail the build.** A suspected problem is shown in the result but never blocks.
* **Redacted.** Output and SARIF quote no password, key or community string.

## GitHub Actions

```yaml
name: config-audit
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.10" }
      - run: pip install -r backend/requirements.txt
      - run: cd backend && python -m app.cli scan ../configs --fail-on high --sarif ../netaudit.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: netaudit.sarif }
```

The upload step shows each problem on its line in the pull request, under *Security → Code scanning*.
