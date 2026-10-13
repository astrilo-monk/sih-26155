"""
The checks are data (``backend/data/controls.json``): a new check, framework mapping or framework is an edit to
that file. The file is validated when it loads, so a mistake stops the service instead of silently deciding nothing.
"""

import json

import pytest

from app.controls.catalog import CONTROLS, DATA, FRAMEWORKS, PHASES, CatalogError, load
from app.controls.evaluate import evaluate_control
from app.controls.judges import BUILT_IN, judge_for
from app.facts.predicates import SecurityFact
from app.models.normalized import DeviceInfo, NormalizedConfig, Vendor
from app.models.results import Assurance, Evidence, Status


def _doc():
    return json.loads(DATA.read_text(encoding="utf-8"))


def _write(tmp_path, doc):
    path = tmp_path / "controls.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_every_check_loads_with_a_judge_and_a_phase():
    assert len(CONTROLS) == len(_doc()["controls"])
    for control in CONTROLS.values():
        assert control.phase in PHASES and judge_for(control) is not None
    assert FRAMEWORKS == ("NIST_800_53", "CIS", "DISA_STIG", "ISO_27001")


def test_a_check_written_only_in_data_is_evaluated(tmp_path):
    """No code: a new boolean predicate and a rule judge, declared in the file."""
    doc = _doc()
    doc["predicates"] = {"mgmt.ftp.enabled": "bool"}
    doc["controls"].append({
        "id": "SVC-900", "title": "FTP Server Enabled", "question": "Is the FTP server off?",
        "kind": "prohibition", "severity": "high", "category": "management", "needs": ["mgmt.ftp.enabled"],
        "judge": {"forbid": True, "fail": "The FTP server is enabled.", "advice": "Turn the FTP server off."},
        "phase": 2, "mappings": [{"framework": "PCI_DSS", "version": "4.0", "id": "2.2.4",
                                  "title": "Only necessary services are enabled"}],
    })
    controls, declared = load(_write(tmp_path, doc))
    control = controls["SVC-900"]
    assert declared == {"mgmt.ftp.enabled": "bool"} and control.mappings[0].framework == "PCI_DSS"
    config = NormalizedConfig(device=DeviceInfo(vendor=Vendor.UNKNOWN), raw_config="ftp-server enable",
                              raw_lines=["ftp-server enable"])

    def fact(value):
        return SecurityFact("mgmt.ftp.enabled", value, Assurance.CONFIRMED,
                            Evidence(line_numbers=[1], text=["ftp-server enable"]))

    on = evaluate_control(control, [fact(True)], config)
    off = evaluate_control(control, [fact(False)], config)
    absent = evaluate_control(control, [], config)
    assert on[0].status == Status.FAIL and on[0].reason == "The FTP server is enabled."
    assert off[0].status == Status.PASS
    assert absent[0].status == Status.NOT_CONFIGURED  # absence is never a pass


@pytest.mark.parametrize("change, message", [
    (lambda c: c.update(needs=["mgmt.no_such.thing"]), "unknown predicate"),
    (lambda c: c.update(phase=7), "phase"),
    (lambda c: c.update(severity="catastrophic"), "catastrophic"),
])
def test_a_mistake_in_the_file_stops_the_load(tmp_path, change, message):
    doc = _doc()
    change(doc["controls"][0])
    with pytest.raises(CatalogError, match=message):
        load(_write(tmp_path, doc))


def test_an_unknown_judge_is_refused():
    from dataclasses import replace

    with pytest.raises(CatalogError, match="no built-in judge"):
        judge_for(replace(CONTROLS["MGMT-001"], judge="guess"))
    with pytest.raises(CatalogError, match="exactly one"):
        judge_for(replace(CONTROLS["MGMT-001"], judge={"forbid": True, "require": True}))
    assert set(BUILT_IN) >= {c.judge for c in CONTROLS.values() if isinstance(c.judge, str)}


def test_reference_commands_name_known_inputs_only():
    """A {value} in a reference command is filled from an operator input; anything else must be <value>."""
    from app.remediation.recipes import INPUTS

    for control in CONTROLS.values():
        for lines in control.remediation.values():
            for line in lines:
                import re
                assert set(re.findall(r"\{(\w+)\}", line)) <= set(INPUTS), (control.control_id, line)
