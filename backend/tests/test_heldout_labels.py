"""
The held-out labels (``benchmark/labels.json`` → ``heldout``) are well formed, checked without running the engine:
every label names a real control, has its evidence, and every cited line exists and says the cited text.
The files are git-ignored (``datasets/pybatfish``): without them only the label shapes are checked.
"""

import json
from pathlib import Path

import pytest

from app.controls.catalog import CONTROLS

ROOT = Path(__file__).resolve().parents[2]
HELDOUT = {k: v for k, v in json.loads((ROOT / "benchmark" / "labels.json").read_text(encoding="utf-8"))["heldout"].items()
           if not k.startswith("_")}


def test_there_are_enough_files_and_labels():
    assert len(HELDOUT) >= 6 and sum(len(v["fail"]) + len(v["pass"]) for v in HELDOUT.values()) >= 30


@pytest.mark.parametrize("name", sorted(HELDOUT))
def test_every_label_names_a_control_and_cites_its_line(name):
    label = HELDOUT[name]
    wanted = [*label["fail"], *label["pass"]]
    assert set(wanted) <= set(CONTROLS) and not set(label["fail"]) & set(label["pass"])
    assert set(label["evidence"]) == set(wanted)
    path = ROOT / name
    if not path.exists():
        pytest.skip(f"{name} not fetched (datasets/ is git-ignored)")
    lines = path.read_text(encoding="utf-8").splitlines()
    for control, (number, text) in label["evidence"].items():
        if number is not None:
            assert 1 <= number <= len(lines) and lines[number - 1].strip().startswith(text.strip()), (control, number)
