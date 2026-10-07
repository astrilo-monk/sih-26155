"""The published benchmark never gets worse: no misses, no false alarms, detection at least what RESULTS.md says."""

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "benchmark.py"


def test_benchmark_holds(seeded_adaptive_db):
    spec = importlib.util.spec_from_file_location("benchmark", SCRIPT)
    benchmark = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(benchmark)
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        report = benchmark.run(isolate=False)
    for group, floor in (("planted", 19), ("fixtures", 89)):
        fails, passes = benchmark.totals(report[group])
        assert fails["missed"] == 0 and passes["false_alarm"] == 0, (group, fails, passes)
        assert fails["detected"] >= floor, (group, fails)
    # held-out files are git-ignored: checked wherever they are fetched
    fails, passes = benchmark.totals(report.get("heldout", []))
    assert fails["missed"] == 0 and passes["false_alarm"] == 0, ("heldout", fails, passes)
