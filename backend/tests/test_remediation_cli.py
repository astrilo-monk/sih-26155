"""
Remediation as device commands (``app.remediation.cli``) and in lockout-safe order (``phase`` in
data/controls.json): what the problem statement calls device-specific, step-by-step CLI command sequences.
Only a change the rescan verified is rendered; anything else is labelled as an unverified reference.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.controls.catalog import CONTROLS
from app.main import app
from app.remediation.cli import cli_steps, dialect
from app.remediation.engine import FIX_ORDER, remediate_all

DEMO = Path(__file__).resolve().parents[2] / "demo-sih"


@pytest.mark.parametrize("before, after, expected", [
    # IOS: a child line goes under its block; a removed line is negated
    ("hostname r1\nline vty 0 4\n transport input telnet\n!\nip http server\nend\n",
     "hostname r1\nline vty 0 4\n transport input ssh\n!\nend\n",
     ["configure terminal", "line vty 0 4", "   transport input ssh", "exit", "no ip http server", "end",
      "write memory"]),
    # FortiOS: parents re-entered, set / unset, then next / end
    ("config system admin\n    edit \"admin\"\n        set trusthost1 0.0.0.0 0.0.0.0\n        set guest x\n    next\nend\n",
     "config system admin\n    edit \"admin\"\n        set trusthost1 10.0.0.0 255.255.255.0\n    next\nend\n",
     ["config system admin", "   edit \"admin\"", "      set trusthost1 10.0.0.0 255.255.255.0", "      unset guest",
      "   next", "end"]),
    # Junos braces: each line becomes one set / delete command with its full path
    ("system {\n    services {\n        telnet;\n        ssh;\n    }\n}\n",
     "system {\n    services {\n        ssh;\n    }\n    login {\n        message \"hi\";\n    }\n}\n",
     ["configure", "delete system services telnet", "set system login message \"hi\"", "commit"]),
    # set-style: the line is the command
    ("set deviceconfig system service disable-telnet no\n",
     "set deviceconfig system service disable-telnet yes\n",
     ["configure", "set deviceconfig system service disable-telnet yes", "commit"]),
])
def test_a_change_is_written_as_the_dialects_commands(before, after, expected):
    assert cli_steps(before, after) == expected


def test_a_comment_is_not_mistaken_for_a_block_header():
    before = "ip ssh version 1\n! comment\nend\n"
    assert cli_steps(before, before.replace("version 1", "version 2")) == [
        "configure terminal", "ip ssh version 2", "end", "write memory"]


@pytest.mark.parametrize("text", ['{"ACL_TABLE": {}}', 'resource "aws_security_group" "x" {\n}\n', "<config/>"])
def test_a_file_that_is_not_a_cli_gets_no_commands(text):
    assert dialect(text.splitlines()) is None


def test_fixes_are_ordered_so_the_session_is_never_cut():
    """SSH v2 before Telnet goes off; restricting management access comes last."""
    order = FIX_ORDER
    assert order.index("MGMT-007") < order.index("MGMT-001") < order.index("MGMT-003")
    assert [CONTROLS[c].phase for c in order] == sorted(CONTROLS[c].phase for c in order)
    plan = remediate_all((DEMO / "cisco_oneclick.cfg").read_text(encoding="utf-8"), {})
    phases = [CONTROLS[o.control_id].phase for o in plan.outcomes]
    assert phases == sorted(phases)


def test_the_plan_and_the_pdf_carry_the_step_by_step_commands():
    client = TestClient(app)
    text = (DEMO / "cisco_oneclick.cfg").read_bytes()
    scan = client.post("/api/scan", files=[("files", ("r.cfg", text, "text/plain"))]).json()
    device = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    assert device["cli"][0] == "configure terminal" and device["cli"][-1] == "write memory"
    fixed = [r for r in device["remediations"] if r["status"] == "fixed"]
    assert fixed and all(r["cli"] and r["phase_name"] for r in fixed)
    # every fixed control's commands appear in the plan sequence, in phase order
    assert [r["phase"] for r in device["remediations"]] == sorted(r["phase"] for r in device["remediations"])
    telnet = next(r for r in fixed if r["rule_id"] == "MGMT-001")
    assert "   transport input ssh" in telnet["cli"]

    from app.reporting.report import remediation_block
    from app.api.schemas import DeviceRemediationPlanSchema

    blocks = remediation_block(DeviceRemediationPlanSchema(**device), 0)
    mono = [payload for kind, payload in blocks if kind == "mono"]
    assert mono[0] == device["cli"]


def test_an_unverified_fix_shows_the_vendor_reference_labelled_as_such(seeded_adaptive_db):
    client = TestClient(app)
    junos = (Path(__file__).parent / "fixtures" / "seed_dialects" / "junos_set.conf").read_bytes()
    scan = client.post("/api/scan", files=[("files", ("j.conf", junos, "text/plain"))]).json()
    device = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    refs = [r for r in device["remediations"] if r["reference_cli"]]
    assert refs and all(r["status"] != "fixed" and r["reference_source"] == "Juniper Junos" for r in refs)
    assert all(r["reference_cli"][0] == "configure" and r["reference_cli"][-1] == "commit" for r in refs)
