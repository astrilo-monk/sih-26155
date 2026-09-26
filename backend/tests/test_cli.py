"""Command line for CI (app/cli.py): exit codes follow decided FAILs, SARIF points at the lines, secrets stay out."""

import json
from pathlib import Path

import pytest

from app import cli

VULNERABLE = "!\nhostname CI-01\n!\nsnmp-server community CiSecretCommunity RW\n!\nline vty 0 4\n transport input telnet\n!\n"
CLEAN = Path(__file__).parent / "fixtures" / "cisco_secure.cfg"


@pytest.fixture(autouse=True)
def _db(seeded_adaptive_db, monkeypatch):
    monkeypatch.setattr(cli, "isolated_engine", lambda db=None: None)  # the fixture already isolated it


def test_a_decided_problem_at_the_threshold_fails_the_build_and_sarif_cites_the_line(tmp_path, capsys):
    cfg = tmp_path / "edge.cfg"
    cfg.write_text(VULNERABLE)
    out = tmp_path / "out.sarif"
    assert cli.main(["scan", str(cfg), "--sarif", str(out)]) == 1
    assert "FAILED" in capsys.readouterr().out

    report = json.loads(out.read_text())
    telnet = next(r for r in report["runs"][0]["results"] if r["ruleId"] == "MGMT-001")
    location = telnet["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"].endswith("edge.cfg") and location["region"]["startLine"] == 6  # line vty 0 4
    assert "CiSecretCommunity" not in out.read_text()


def test_the_threshold_decides_the_exit_code():
    assert cli.decided_failures({"results": [{"status": "fail", "assurance": "heuristic", "severity": "critical"}]},
                                "low") == []  # suspected problems never fail a build
    assert cli.main(["scan", str(CLEAN), "--fail-on", "critical"]) == 0


def test_bad_input_is_exit_2(tmp_path, capsys):
    assert cli.main(["scan", str(tmp_path / "missing.cfg")]) == 2
    (tmp_path / "empty").mkdir()
    assert cli.main(["scan", str(tmp_path / "empty")]) == 2
    assert "no files" in capsys.readouterr().err
