"""Prove every attack path and its fix, and record it in ``backend/data/path_validation.json``.

    python backend/scripts/build_path_validation.py

Runs the positive / negative configurations of ``tests/test_path_proof.py`` through the real pipeline (shipped
knowledge, no AI) and writes the outcome with the commit, the date and the catalog's hash. The Attack paths page
and the PDF cite the record only while its hash matches the catalog.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
OUT = BACKEND / "data" / "path_validation.json"


def main() -> int:
    import logging
    logging.disable(logging.WARNING)
    from app.analysis.attack_paths import CHAINS, catalog_hash
    from app.api.routes.scan import run_scan
    from app.cli import isolated_engine
    from tests.test_path_proof import EXPECTED, FIXTURES

    isolated_engine()
    chains: dict[str, list[dict]] = {}
    for case, (positive, negative, steps, fix_step, _) in sorted(EXPECTED.items()):
        scan = lambda name: run_scan([(name, (FIXTURES / name).read_text(encoding="utf-8"))]).model_dump()["attack_paths"]
        pos, neg = scan(positive), scan(negative)
        chain = case.split(" ")[0]
        shown = [{c["control_id"] for c in s["controls"]} for s in pos[0]["steps"]] if len(pos) == 1 else None
        ok = ([p["path_id"] for p in pos] == [chain] and shown == steps and pos[0]["break_step"] == fix_step
              and neg == [])
        chains.setdefault(chain, []).append({"case": case, "positive": positive, "negative": negative,
                                             "fix_step": fix_step, "passed": ok})
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=BACKEND, capture_output=True,
                            text=True).stdout.strip() or "unknown"
    record = {"generated": date.today().isoformat(), "commit": commit, "catalog_hash": catalog_hash(),
              "passed": all(r["passed"] for rs in chains.values() for r in rs) and set(chains) == {c.path_id for c in CHAINS},
              "chains": chains}
    OUT.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"{'passed' if record['passed'] else 'FAILED'}: {sum(len(v) for v in chains.values())} cases, "
          f"{len(chains)} chains -> {OUT.relative_to(BACKEND.parent)}")
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
