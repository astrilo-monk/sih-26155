"""
Phase 9 -framework views over existing control results, persistent recognizers across a
backend restart, and persistent stores that never hold configuration secrets.
"""

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.api.routes.scan import get_scan_store
from app.controls.catalog import CIS, CONTROLS, NIST, NIST_VERSION
from app.main import app
from app.models.results import Assurance, Status

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
FIXTURES = BACKEND / "tests" / "fixtures"

SECRET_CONFIG = """system-name EDGE
time-sync server 10.1.1.1
remote-console protocol telnet
syslog host 10.2.2.2 key FakeSyslogKey5
audit-stream destination 10.3.3.3
"""


def _scan(client, *files) -> dict:
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        response = client.post("/api/scan", files=[("files", (name, data, "text/plain")) for name, data in files])
    assert response.status_code == 200, response.text
    return response.json()


def _views(scan: dict) -> dict:
    return {(v["framework"], v["version"]): v for v in scan["frameworks"]}


def _requirement(view: dict, requirement_id: str) -> dict:
    return next(r for r in view["requirements"] if r["requirement_id"] == requirement_id)


# ── framework views ─────────────────────────────────────────────────────────

def test_framework_view_regroups_existing_results_without_reevaluating():
    scan = _scan(TestClient(app), ("c.cfg", (FIXTURES / "cisco_vulnerable.cfg").read_bytes()))
    views = _views(scan)
    nist = views[(NIST, NIST_VERSION)]

    expected = {m.requirement_id for c in CONTROLS.values() for m in c.mappings if m.framework == NIST}
    assert {r["requirement_id"] for r in nist["requirements"]} == expected
    statuses = {}
    for r in scan["results"]:
        statuses.setdefault(r["control_id"], set()).add(r["status"])
    for requirement in nist["requirements"]:
        for control in requirement["controls"]:
            assert control["status"] in statuses[control["control_id"]]

    ac17 = _requirement(nist, "AC-17(2)")
    assert {c["control_id"] for c in ac17["controls"]} == {"MGMT-001", "MGMT-002", "MGMT-007"}
    assert ac17["status"] == "fail" and not ac17["provisional"]
    telnet = next(c for c in ac17["controls"] if c["control_id"] == "MGMT-001")
    assert telnet["decisive"] and telnet["assurance"] == "parser" and 87 in telnet["evidence"]["line_numbers"]

    cis = [version for framework, version in views if framework == CIS]
    assert cis and all(version.startswith("Cisco IOS XE") for version in cis)
    assert all(v["coverage"] == 100 for v in views.values())  # every mapped Cisco control decided


def test_pass_needs_every_mapped_control_decisive_and_ai_proposals_never_count():
    client = TestClient(app)
    scan = _scan(client, ("s.cfg", (FIXTURES / "cisco_secure.cfg").read_bytes()))
    assert _requirement(_views(scan)[(NIST, NIST_VERSION)], "AC-17(2)")["status"] == "pass"

    for r in get_scan_store()[scan["scan_id"]]["result"].device_results[0]:
        if r.control_id == "MGMT-007":
            r.status, r.proposed_status, r.assurance = Status.UNKNOWN, Status.PASS, Assurance.AI_VERIFIED
    again = client.get(f"/api/scan/{scan['scan_id']}").json()
    ac17 = _requirement(_views(again)[(NIST, NIST_VERSION)], "AC-17(2)")
    assert ac17["status"] == "partial" and ac17["provisional"]
    ssh = next(c for c in ac17["controls"] if c["control_id"] == "MGMT-007")
    assert ssh["proposed_status"] == "pass" and not ssh["decisive"]


def test_unknown_vendor_gets_no_product_benchmark_and_no_decisive_requirement():
    scan = _scan(TestClient(app), ("u.cfg", (REPO / "sample" / "unknown.cfg").read_bytes()))
    views = _views(scan)
    assert not any(f == "CIS" for f, _ in views)  # CIS items are Cisco / FortiGate product benchmarks
    for view in views.values():  # the vendor-neutral frameworks still apply, undecided
        assert view["coverage"] == 0
        assert {r["status"] for r in view["requirements"]} <= {"unknown", "not_configured"}
    nist = views[(NIST, NIST_VERSION)]
    assert _requirement(nist, "SC-8")["provisional"]  # the suspected Telnet FAIL is heuristic


def test_multi_device_scan_scopes_benchmarks_per_vendor():
    scan = _scan(TestClient(app), ("c.cfg", (FIXTURES / "cisco_vulnerable.cfg").read_bytes()),
                 ("f.cfg", (FIXTURES / "fortinet_secure.cfg").read_bytes()))
    views = _views(scan)
    cis = {version for framework, version in views if framework == CIS}
    assert any(v.startswith("Cisco") for v in cis) and any(v.startswith("FortiGate") for v in cis)
    for (framework, version), view in views.items():
        if framework == CIS:
            devices = {c["config_index"] for r in view["requirements"] for c in r["controls"]}
            assert devices == ({0} if version.startswith("Cisco") else {1})
    sc8 = _requirement(views[(NIST, NIST_VERSION)], "SC-8")
    assert {c["config_index"] for c in sc8["controls"]} == {0, 1}


# ── secrets never persisted ─────────────────────────────────────────────────

def _database_text(path: Path) -> str:
    conn = sqlite3.connect(path)
    try:
        tables = [t for (t,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        return "\n".join(str(row) for t in tables for row in conn.execute(f"SELECT * FROM {t}"))
    finally:
        conn.close()


def test_rejected_line_with_a_secret_is_stored_redacted_and_still_matches(isolated_adaptive_db):
    client = TestClient(app)
    scan = _scan(client, ("s.cfg", SECRET_CONFIG.encode()))
    lines = {r["control_id"]: r for r in scan["results"]}
    assert 4 in lines["LOG-001"]["evidence"]["line_numbers"]

    rejected = client.post(f"/api/adaptive/scans/{scan['scan_id']}/provisional/reject",
                           json={"control_id": "LOG-001", "line_number": 4})
    assert rejected.status_code == 200, rejected.text
    stored = _database_text(isolated_adaptive_db)
    assert "FakeSyslogKey5" not in stored and "syslog host 10.2.2.2" in stored

    rescan = _scan(client, ("s.cfg", SECRET_CONFIG.encode()))
    log = next(r for r in rescan["results"] if r["control_id"] == "LOG-001")
    assert 4 not in log["evidence"]["line_numbers"]  # the redacted key still matches the raw line


def test_a_line_holding_a_secret_never_becomes_a_recognizer(isolated_adaptive_db):
    client = TestClient(app)
    scan = _scan(client, ("s.cfg", SECRET_CONFIG.encode()))
    body = {"control_id": "LOG-001", "line_number": 4}
    draft = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers/draft", json=body).json()
    assert any("secret" in e for e in draft["errors"])
    saved = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers", json=body)
    assert saved.status_code == 422
    assert "FakeSyslogKey5" not in _database_text(isolated_adaptive_db)
    assert client.get("/api/adaptive/mappings").json() == []


# ── recognizers survive a backend restart ───────────────────────────────────

_SAVE = """
import json
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)
text = open("../sample/unknown.cfg", "rb").read()
scan = client.post("/api/scan", files=[("files", ("unknown.cfg", text, "text/plain"))]).json()
saved = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers", json={"control_id": "MGMT-001", "line_number": 71})
print(json.dumps({"status": saved.status_code, "before": next(r for r in scan["results"] if r["control_id"] == "MGMT-001")["assurance"]}))
"""

_RESCAN = """
import json
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)
text = open("../sample/unknown.cfg", "rb").read()
scan = client.post("/api/scan", files=[("files", ("unknown.cfg", text, "text/plain"))]).json()
r = next(r for r in scan["results"] if r["control_id"] == "MGMT-001")
print(json.dumps({"status": r["status"], "assurance": r["assurance"], "lines": r["evidence"]["line_numbers"],
                  "ai_calls": scan["adaptive"]["ai_calls"], "coverage": scan["coverage"],
                  "recognizers": len([m for m in client.get("/api/adaptive/mappings").json()
                                      if m["source"] == "runtime"])}))
"""


def _backend_process(code: str, db: Path) -> dict:
    """A fresh Python process: nothing survives from the previous one except the database file."""
    env = {**os.environ, "ADAPTIVE_DB_PATH": str(db),
           **{key: "" for key in ("GROQ_API_KEY", "GROQ_API_KEY_1", "GROQ_API_KEY_2", "GROQ_API_KEY_3", "GROQ_API_KEY_4")}}
    done = subprocess.run([sys.executable, "-c", code], cwd=BACKEND, env=env, capture_output=True, text=True,
                          timeout=180)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_confirmed_recognizer_survives_restart_and_is_reused_by_a_new_scan(tmp_path):
    db = tmp_path / "persistent.db"
    first = _backend_process(_SAVE, db)
    assert first == {"status": 200, "before": "heuristic"}

    # a real backend process, so the shipped seed recognizers are loaded too: count only what was learned here
    second = _backend_process(_RESCAN, db)  # new process, empty scan store
    assert second == {"status": "fail", "assurance": "confirmed", "lines": [70, 71], "ai_calls": 0,
                      "coverage": second["coverage"], "recognizers": 1}
    assert second["coverage"] > 0

    stored = _database_text(db)
    raw = (REPO / "sample" / "unknown.cfg").read_text(encoding="utf-8").splitlines()
    kept = {"remote-console protocol telnet"}
    assert not [line for line in raw if line.strip() and len(line.strip()) > 12
                and line.strip() not in kept and line.strip() in stored]  # no raw configuration persisted
