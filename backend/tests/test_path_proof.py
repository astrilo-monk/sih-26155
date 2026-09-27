"""
Each attack path and its "fix here" step, proved on two configurations written for it (``fixtures/attack_paths``):
the positive must show exactly that chain, and a copy that applies only the fix must show none of it. The
expectations below were written before the engine ran on these files.

``backend/scripts/build_path_validation.py`` records the same check in ``data/path_validation.json``; a test fails
when that record is older than the chain catalog.
"""

import difflib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.analysis import attack_paths
from app.api.routes.scan import run_scan

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "attack_paths"
VALIDATION = Path(__file__).resolve().parents[1] / "data" / "path_validation.json"

# chain → (positive, negative, the failing checks the positive must show per step, the step to fix, the fix)
EXPECTED = {
    "remote-takeover": ("remote_takeover_pos.cfg", "remote_takeover_neg.cfg",
                        [{"MGMT-003"}, {"MGMT-001"}, {"MGMT-008"}], "Reach the login", ["access-class 10 in"]),
    "password-guessing": ("password_guessing_pos.cfg", "password_guessing_neg.cfg",
                          [{"MGMT-003"}, {"AUTH-001"}, {"LOG-001"}], "Reach the login", ["access-class 10 in"]),
    "snmp-exposure": ("snmp_exposure_pos.cfg", "snmp_exposure_neg.cfg",
                      [{"MGMT-004"}, {"MGMT-011"}, {"LOG-001"}], "Guess the community",
                      ["snmp-server community n0c-R3ad0nly RO"]),
    "perimeter-bypass": ("perimeter_bypass_pos.cfg", "perimeter_bypass_neg.cfg",
                         [{"BOUNDARY-001"}, {"BOUNDARY-002"}], "Pass the filter",
                         ["permit ip 10.0.0.0 0.255.255.255 any"]),
    # the same chain read by shipped seeds on an unparsed dialect (set-style Junos)
    "snmp-exposure (seed knowledge)": ("snmp_exposure_junos_pos.conf", "snmp_exposure_junos_neg.conf",
                                       [{"MGMT-004"}, {"MGMT-011"}, {"LOG-001"}], "Guess the community",
                                       ["set snmp community n0c-R3ad0nly authorization read-only"]),
}


def _paths(name: str) -> list[dict]:
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        return run_scan([(name, (FIXTURES / name).read_text(encoding="utf-8"))]).model_dump(mode="json")["attack_paths"]


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_the_positive_shows_exactly_its_chain(seeded_adaptive_db, case):
    positive, _, steps, fix_step, _ = EXPECTED[case]
    chain = case.split(" ")[0]
    paths = _paths(positive)
    assert [p["path_id"] for p in paths] == [chain]
    shown = [{c["control_id"] for c in step["controls"]} for step in paths[0]["steps"]]
    assert shown == steps and paths[0]["break_step"] == fix_step


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_applying_only_the_fix_closes_the_chain(seeded_adaptive_db, case):
    _, negative, _, _, _ = EXPECTED[case]
    assert _paths(negative) == []


@pytest.mark.parametrize("case", sorted(EXPECTED))
def test_the_negative_differs_only_by_the_fix(case):
    positive, negative, _, _, fix = EXPECTED[case]
    diff = difflib.ndiff((FIXTURES / positive).read_text(encoding="utf-8").splitlines(),
                         (FIXTURES / negative).read_text(encoding="utf-8").splitlines())
    assert [line[2:].strip() for line in diff if line.startswith("+ ")] == fix


def test_every_chain_is_proved():
    assert {case.split(" ")[0] for case in EXPECTED} == {c.path_id for c in attack_paths.CHAINS}


def test_the_recorded_validation_is_current():
    record = json.loads(VALIDATION.read_text(encoding="utf-8"))
    assert record["catalog_hash"] == attack_paths.catalog_hash(), "run backend/scripts/build_path_validation.py"
    assert record["passed"] and set(record["chains"]) == {c.path_id for c in attack_paths.CHAINS}


def test_the_scan_and_the_report_cite_the_proof(seeded_adaptive_db):
    from app.reporting.report import attack_paths_block

    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        scan = run_scan([("p.cfg", (FIXTURES / "snmp_exposure_pos.cfg").read_text(encoding="utf-8"))])
    record = json.loads(VALIDATION.read_text(encoding="utf-8"))
    assert scan.path_validation == {"commit": record["commit"], "generated": record["generated"]}
    assert any(kind == "p" and "positive and a negative configuration" in text
               for kind, text in attack_paths_block(scan, 0))
