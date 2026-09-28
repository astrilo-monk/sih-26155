"""
Independent citation check: every benchmark and demo file through the real pipeline, then checked against the
uploaded text with this file's own reading, never the engine's.

* every cited line exists and carries the cited text (a ``<SECRET:…>`` placeholder stands for the value it hid)
* every attack-path step cites a decided FAIL of the same device, on lines that result cites
* posture and coverage recomputed here from the returned results equal the returned ones

The text a citation is checked against is the uploaded file, except for a JSON export: the engine reads (and
cites) its flattened lines by design (``docs/architecture.md`` §3). A Terraform line is cited as its block
header followed by the block's own settings, so the uploaded header must start the cited text.
"""

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.api.routes.scan import run_scan
from app.structure.structured import flatten_json

ROOT = Path(__file__).resolve().parents[2]
LABELS = json.loads((ROOT / "benchmark" / "labels.json").read_text(encoding="utf-8"))
FILES = sorted({*LABELS["planted"], *LABELS["fixtures"], *(f"backend/tests/fixtures/demo/{p.name}" for p in (ROOT / "backend" / "tests" / "fixtures" / "demo").glob("*.cfg"))})

DECISIVE = {"parser", "confirmed", "default"}
WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1}
_SECRET = re.compile(r"<SECRET:[\w-]+>")


def _scan(sources: list[tuple[str, str]]) -> dict:
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        return run_scan(sources).model_dump(mode="json")


def _normal(text: str) -> str:
    """Whitespace, quotes and block punctuation do not change what a line says."""
    return " ".join(re.sub(r'["{}]|\s=\s', " ", text).split())


def _says(cited: str, source: str, prefix: bool) -> bool:
    """Does the source line say the cited text? A placeholder matches the one value it replaced."""
    if prefix:  # a Terraform citation: the uploaded block header, then what the block states
        return _normal(cited).startswith(_normal(source))
    parts = re.split(f"({_SECRET.pattern})", _normal(cited))
    pattern = "".join(r"\S+" if _SECRET.fullmatch(part) else re.escape(part) for part in parts)
    return re.fullmatch(pattern, _normal(source)) is not None


def _source_lines(name: str) -> list[str]:
    text = (ROOT / name).read_text(encoding="utf-8")
    if name.endswith(".json"):
        return flatten_json(text)
    return text.splitlines()


def _check_citations(name: str, scan: dict, lines: list[str]) -> None:
    prefix = name.endswith(".tf")
    for r in scan["results"]:
        numbers, texts = r["evidence"]["line_numbers"], r["evidence"]["lines"]
        assert all(1 <= n <= len(lines) for n in numbers), (name, r["control_id"], numbers)
        # evidence lists its cited lines in order, one text per number
        if texts and len(texts) == len(numbers):
            for n, text in zip(numbers, texts):
                assert _says(text, lines[n - 1], prefix), (name, r["control_id"], n, text, lines[n - 1])


def _check_attack_paths(name: str, scan: dict, lines: list[str]) -> None:
    decided: dict[tuple, set[int]] = {}  # a control may fail once per scope (one per SNMP community)
    for r in scan["results"]:
        if r["status"] == "fail" and r["assurance"] in DECISIVE:
            decided.setdefault((r["config_index"], r["control_id"]), set()).update(r["evidence"]["line_numbers"])
    for path in scan["attack_paths"]:
        for step in path["steps"]:
            for control in step["controls"]:
                cited = decided.get((path["config_index"], control["control_id"]))
                assert cited is not None, (name, path["path_id"], control["control_id"], "not a decided FAIL here")
                for line in control["lines"]:
                    assert line["number"] in cited, (name, control["control_id"], line)
                    assert _says(line["text"], lines[line["number"] - 1], name.endswith(".tf")), (name, line)


def _posture(results: list[dict]) -> tuple:
    """Posture and coverage, written again from the definition: each control counts once per device, a FAIL at
    its worst severity, only decisive verdicts decide, N/A is not applicable."""
    by_control: dict[tuple, list[dict]] = {}
    for r in results:
        by_control.setdefault((r["config_index"], r["control_id"]), []).append(r)
    passed = failed = undecided = 0
    for group in by_control.values():
        fails = [r for r in group if r["status"] == "fail"]
        if fails:
            weight = max(WEIGHTS[r["severity"]] for r in fails)
            if any(r["assurance"] in DECISIVE for r in fails):
                failed += weight
            else:
                undecided += weight
        elif group[0]["status"] == "n_a":
            continue
        elif group[0]["status"] == "pass" and group[0]["assurance"] in DECISIVE:
            passed += WEIGHTS[group[0]["severity"]]
        else:
            undecided += WEIGHTS[group[0]["severity"]]
    applicable = passed + failed + undecided
    posture = round(passed * 100 / (passed + failed)) if passed + failed else None
    return posture, round((passed + failed) * 100 / applicable) if applicable else 0


@pytest.mark.parametrize("name", FILES)
def test_every_citation_is_in_the_uploaded_file(seeded_adaptive_db, name):
    scan = _scan([(Path(name).name, (ROOT / name).read_text(encoding="utf-8"))])
    lines = _source_lines(name)
    _check_citations(name, scan, lines)
    _check_attack_paths(name, scan, lines)
    assert _posture(scan["results"]) == (scan["posture"], scan["coverage"]), name


def test_a_fleet_scan_cites_each_device_in_its_own_file(seeded_adaptive_db):
    names = [f"backend/tests/fixtures/demo/{p.name}" for p in sorted((ROOT / "backend" / "tests" / "fixtures" / "demo").glob("*.cfg"))]
    scan = _scan([(Path(n).name, (ROOT / n).read_text(encoding="utf-8")) for n in names])
    for index, name in enumerate(names):
        own = {**scan, "results": [r for r in scan["results"] if r["config_index"] == index],
               "attack_paths": [p for p in scan["attack_paths"] if p["config_index"] == index]}
        _check_citations(name, own, _source_lines(name))
        _check_attack_paths(name, own, _source_lines(name))
    assert _posture(scan["results"]) == (scan["posture"], scan["coverage"])
