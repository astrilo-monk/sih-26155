"""
Command line for CI pipelines: check configurations before they reach a device.

    python -m app.cli scan configs/ --fail-on high --sarif netaudit.sarif
    python -m app.cli scan edge.cfg fw.conf --json
    python -m app.cli ledger-verify ledger-export.json --public-key <hex>

The same engine as the web app, without the server. It runs on a throwaway database holding the shipped
knowledge only, with AI off, so the same files always give the same answer and nothing is written to the
deployment's database. ``--db`` uses a knowledge database instead (to include what was taught there).

Exit codes: 0 no decided FAIL at or above ``--fail-on``; 1 there is one; 2 bad arguments or unreadable input.
Only decided FAILs count, the same rule as scoring: a suspected problem never fails a build.

``ledger-verify`` checks an exported audit ledger (``GET /api/ledger/export``) on any machine, offline: every
hash link and every Ed25519 signature, against a public key you kept apart from the server. Exit 0 intact, 1 not.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
from pathlib import Path

DECISIVE = {"parser", "confirmed", "default"}
SEVERITIES = ["low", "medium", "high", "critical"]
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def isolated_engine(db: Path | None = None) -> None:
    """Shipped knowledge only (or ``db``), and no AI whatever the local .env says."""
    import app.config as config
    from app.db import database

    settings = config.settings
    fresh = db is None
    db = db or Path(tempfile.mkdtemp()) / "netaudit.db"
    settings.adaptive_db_path, settings.database_url, settings.api_key = db, "", ""
    # a throwaway database gets a throwaway signing key, never the deployment's
    settings.ledger_key_path, settings.ledger_signing_key = db.parent / "ledger_signing_key.pem", ""
    settings.ai_judge_max_calls_per_scan, settings.local_ai_url = 0, ""
    for name in [n for n in type(settings).model_fields if n.startswith("groq_api_key")]:
        setattr(settings, name, "")
    if fresh:
        database._SEEDED = set()
    database.init_db(db)


def decided_failures(scan: dict, fail_on: str) -> list[dict]:
    floor = SEVERITIES.index(fail_on)
    return [r for r in scan["results"] if r["status"] == "fail" and r.get("assurance") in DECISIVE
            and SEVERITIES.index(r["severity"]) >= floor]


def sarif(scan: dict, files: list[str]) -> dict:
    """SARIF 2.1.0: every decided FAIL, on the lines it cites, so code review shows it next to the line."""
    failing = [r for r in scan["results"] if r["status"] == "fail" and r.get("assurance") in DECISIVE]
    rules = {r["control_id"]: {"id": r["control_id"], "shortDescription": {"text": r["title"]},
                               "fullDescription": {"text": r["question"]}} for r in failing}
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "NetAuditAI", "rules": sorted(rules.values(), key=lambda r: r["id"])}},
            "results": [{
                "ruleId": r["control_id"],
                "level": SARIF_LEVEL[r["severity"]],
                "message": {"text": f"{r['title']}: {r['reason']}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": Path(files[r["config_index"]]).as_posix()},
                    "region": {"startLine": n}}} for n in (r["evidence"]["line_numbers"] or [1])[:1]],
            } for r in failing],
        }],
    }


def _files(paths: list[str]) -> list[Path]:
    out = []
    for p in map(Path, paths):
        if p.is_dir():
            out += sorted(f for f in p.rglob("*") if f.is_file() and not f.name.startswith("."))
        elif p.is_file():
            out.append(p)
        else:
            raise FileNotFoundError(p)
    return out


def ledger_verify(path: Path, public_key: str, allow_unsigned: bool = False) -> int:
    from app.ledger import key_id, verify_rows

    try:
        rows = json.loads(path.read_text(encoding="utf-8"))["entries"]
        trusted = {key_id(public_key.strip()): public_key.strip()}
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"netaudit: cannot read the ledger export: {e}", file=sys.stderr)
        return 2
    result = verify_rows(rows, trusted)
    if not result["ok"]:
        print(f"TAMPERED: entry #{result['broken_at']}: {result['reason']}")
        return 1
    print(f"intact: {result['entries']} entries, {result['signed']} signed by key {key_id(public_key.strip())}"
          + (f", {result['unsigned']} recorded before signing" if result["unsigned"] else ""))
    if result["unsigned"] and not allow_unsigned:
        # an unsigned entry is protected by the hash chain alone, which a database writer can recompute
        print("NOT PROVEN: unsigned entries are not protected by a signature (--allow-unsigned accepts them)")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    from app.controls.catalog import FRAMEWORKS

    parser = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__.split("\n\n")[0].strip())
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="check configuration files")
    scan.add_argument("paths", nargs="+", help="configuration files or directories")
    scan.add_argument("--fail-on", choices=SEVERITIES, default="high",
                      help="exit 1 when a decided FAIL at or above this severity exists (default: high)")
    scan.add_argument("--framework", choices=FRAMEWORKS)
    scan.add_argument("--sarif", metavar="FILE", help="also write SARIF 2.1.0 here")
    scan.add_argument("--json", action="store_true", help="print the full scan result as JSON instead of a summary")
    scan.add_argument("--policy", metavar="FILE", help="organisation policy (JSON) to check against")
    scan.add_argument("--db", type=Path, help="knowledge database to use instead of the shipped knowledge")
    check = sub.add_parser("ledger-verify", help="check an exported audit ledger offline")
    check.add_argument("export", type=Path, help="the JSON from GET /api/ledger/export")
    check.add_argument("--public-key", required=True, help="the deployment's Ed25519 public key (hex), kept apart")
    check.add_argument("--allow-unsigned", action="store_true",
                       help="accept entries recorded before the ledger was signed (they come first)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.ERROR)
    if args.command == "ledger-verify":
        return ledger_verify(args.export, args.public_key, args.allow_unsigned)
    try:
        files = _files(args.paths)
        sources = [(str(f), f.read_text(encoding="utf-8")) for f in files]
    except (OSError, UnicodeDecodeError) as e:
        print(f"netaudit: cannot read {e}", file=sys.stderr)
        return 2
    if not files:
        print("netaudit: no files to check", file=sys.stderr)
        return 2

    from app.controls import policy
    try:
        chosen = policy.parse(json.loads(Path(args.policy).read_text(encoding="utf-8"))) if args.policy else None
    except (OSError, ValueError) as e:
        print(f"netaudit: policy: {e}", file=sys.stderr)
        return 2

    isolated_engine(args.db)
    from fastapi import HTTPException

    from app.api.routes.scan import run_scan
    try:
        result = run_scan(sources, args.framework, policy=chosen).model_dump(mode="json")
    except HTTPException as e:
        print(f"netaudit: {e.detail}", file=sys.stderr)
        return 2

    names = [str(f) for f in files]
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(sarif(result, names), indent=2), encoding="utf-8")
    blocking = decided_failures(result, args.fail_on)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for i, (name, device) in enumerate(zip(names, result["devices"])):
            fails = [r for r in decided_failures(result, "low") if r["config_index"] == i]
            print(f"{name}: {device.get('vendor')} | score {device.get('posture', '-')} | {len(fails)} problem(s)")
            for r in sorted(fails, key=lambda r: -SEVERITIES.index(r["severity"])):
                lines = ",".join(map(str, r["evidence"]["line_numbers"][:3]))
                print(f"  {r['severity'].upper():8} {r['control_id']:13} {r['title']}" + (f" (line {lines})" if lines else ""))
        print(f"\n{len(blocking)} decided problem(s) at or above {args.fail_on}: "
              + ("FAILED" if blocking else "passed"))
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
