"""
Regenerate ``phase0_findings.json`` — the Phase 0 golden findings.

The snapshot was recorded from the engine *before* the control-first refactor.
Regenerating it replaces that baseline, so do it only for a deliberate,
reviewed change to Cisco/FortiGate findings:

    cd backend
    python tests/snapshots/generate_phase0_snapshots.py --force
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parents[1]
REPO = BACKEND.parent
OUTPUT = HERE / "phase0_findings.json"
SOURCE_DIRS = [
    "backend/tests/fixtures",
    "sample/cisco",
    "sample/cisco/cisco_netaudit_test_configs",
    "sample/frontinet",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Regenerate the Phase 0 findings snapshot")
    parser.add_argument("--force", action="store_true", help="overwrite the existing baseline")
    options = parser.parse_args()
    if OUTPUT.exists() and not options.force:
        print(f"{OUTPUT} exists; pass --force to replace the Phase 0 baseline")
        return 1

    sys.path.insert(0, str(BACKEND))
    import app.config as app_config

    app_config.settings.adaptive_db_path = Path(tempfile.mkdtemp()) / "adaptive.db"

    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    entries, excluded = [], []
    for directory in SOURCE_DIRS:
        for path in sorted((REPO / directory).glob("*.cfg")):
            no_ai = MagicMock(side_effect=AssertionError("AI must not be called"))
            with patch("app.api.routes.scan.interpret_lines", no_ai), \
                 patch("app.api.routes.scan.is_available", return_value=False):
                resp = client.post("/api/scan", files=[("files", (path.name, path.read_bytes(), "text/plain"))])
            resp.raise_for_status()
            data = resp.json()
            rel = path.relative_to(REPO).as_posix()
            vendor = data["devices"][0]["vendor"]
            if vendor == "unknown":
                excluded.append(rel)
                continue
            entries.append({
                "file": rel,
                "vendor": vendor,
                "score": data["score"],
                "findings": sorted([f["rule_id"], f["severity"], f["line_numbers"]] for f in data["findings"]),
            })

    OUTPUT.write_text(json.dumps({"entries": entries, "excluded_unknown_vendor": excluded}, indent=1) + "\n")
    print(f"wrote {len(entries)} snapshots to {OUTPUT} (excluded: {excluded})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
