"""Phase 3 -Scoring v2: posture + coverage over control results."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.analysis.scoring import calculate_posture
from app.controls.catalog import CONTROLS
from app.main import app
from app.models.findings import Severity
from app.models.results import Assurance, ControlResult, FailureDetail, Status

REPO = Path(__file__).resolve().parents[2]
CRITICAL = next(c for c in CONTROLS.values() if c.severity == Severity.CRITICAL).control_id
LOW = next(c for c in CONTROLS.values() if c.severity == Severity.LOW).control_id


def _r(control_id, status, assurance=Assurance.PARSER, severity=None):
    failure = None
    if status == Status.FAIL:
        failure = FailureDetail(severity or CONTROLS[control_id].severity, "d", "i", "r")
    decided = status in (Status.PASS, Status.FAIL)
    return ControlResult(control_id, status, "reason", assurance=assurance if decided else None, failure=failure)


def _all(status, assurance=Assurance.PARSER):
    return [[_r(cid, status, assurance) for cid in CONTROLS]]


def test_all_pass():
    p = calculate_posture(_all(Status.PASS))
    assert (p.posture, p.coverage, p.bounds, p.critical_unassessed) == (100, 100, (100, 100), [])


def test_all_unknown_never_scores():
    for status in (Status.UNKNOWN, Status.NOT_CONFIGURED):
        p = calculate_posture(_all(status))
        assert p.posture is None and p.coverage == 0 and p.bounds == (0, 100)
        assert CRITICAL in p.critical_unassessed


def test_provisional_assurance_is_not_decisive():
    for assurance in (Assurance.HEURISTIC, Assurance.AI_VERIFIED):
        p = calculate_posture(_all(Status.PASS, assurance))
        assert p.posture is None and p.coverage == 0
        p = calculate_posture(_all(Status.FAIL, assurance))
        assert p.posture is None and p.coverage == 0


def test_critical_unknown_sets_flag():
    results = [_r(cid, Status.UNKNOWN if cid == CRITICAL else Status.PASS) for cid in CONTROLS]
    p = calculate_posture([results])
    assert p.critical_unassessed == [CRITICAL] and p.posture == 100 and p.coverage < 100


def test_n_a_excluded_from_coverage():
    results = [_r(cid, Status.N_A if cid == CRITICAL else Status.PASS) for cid in CONTROLS]
    p = calculate_posture([results])
    assert p.coverage == 100 and p.critical_unassessed == []
    assert calculate_posture([[_r(cid, Status.N_A) for cid in CONTROLS]]).coverage == 0


def test_weights_and_bounds():
    other_critical = [c for c in CONTROLS.values() if c.severity == Severity.CRITICAL][1].control_id
    p = calculate_posture([[_r(CRITICAL, Status.PASS), _r(LOW, Status.FAIL), _r(other_critical, Status.UNKNOWN)]])
    assert p.posture == round(10 * 100 / 11)
    assert p.coverage == round(11 * 100 / 21)
    assert p.bounds == (round(10 * 100 / 21), round(20 * 100 / 21))
    assert p.critical_unassessed == [other_critical]


def test_per_scope_fails_count_once_at_worst_severity():
    fails = [_r(CRITICAL, Status.FAIL, severity=Severity.LOW), _r(CRITICAL, Status.FAIL, severity=Severity.HIGH)]
    p = calculate_posture([fails + [_r(LOW, Status.PASS)]])
    assert p.posture == round(1 * 100 / 7)  # HIGH fail (6) counted once vs LOW pass (1)


def test_devices_are_scored_separately_per_control():
    p = calculate_posture([[_r(LOW, Status.PASS)], [_r(LOW, Status.FAIL)]])
    assert p.posture == 50 and p.coverage == 100


def _scan(path):
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        resp = TestClient(app).post("/api/scan", files=[("files", (path.name, path.read_bytes(), "text/plain"))])
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_api_unknown_config_with_nothing_decided_never_shows_100():
    data = _scan(REPO / "sample" / "unknown.cfg")
    assert data["posture"] is None and data["coverage"] == 0
    assert data["critical_unassessed"]


def test_api_confirmed_vendor_has_posture_and_keeps_legacy_score():
    data = _scan(REPO / "backend" / "tests" / "fixtures" / "cisco_vulnerable.cfg")
    assert data["score"] is not None
    assert data["posture"] is not None and data["posture"] < 100 and 0 < data["coverage"] <= 100
    low, high = data["posture_bounds"]
    assert low <= data["posture"] <= high
