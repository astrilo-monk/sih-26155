"""Detection gaps on vendors without a dedicated parser, and two FortiGate misreadings (fixtures/gaps/).

Each vendor has an insecure configuration with planted problems and a hardened one that configures every one of
them correctly. Every planted problem must FAIL with a cited line or a documented default behind it; the hardened
file must FAIL none of those checks. Nothing here may become a guess: a verdict without evidence is the bug.
"""

from pathlib import Path

import pytest

from app.api.routes.scan import run_scan

GAPS = Path(__file__).parent / "fixtures" / "gaps"

# file stem -> the checks its insecure version plants (the hardened version configures each one correctly)
PLANTED = {
    # Not AUTH-001: with no 'retry-options' Junos still ends a session after a few failed passwords (the
    # statement has documented defaults), so silence is not "no limit", and no default is claimed for it
    "junos_hier": ["MGMT-006", "AUTH-004", "BOUNDARY-001"],
    "junos_set": ["MGMT-006", "AUTH-004", "BOUNDARY-001"],
    "panos": ["MGMT-003"],
    "arista": ["MGMT-001", "MGMT-002", "MGMT-005"],
    "huawei": ["MGMT-003", "MGMT-005", "LOG-002", "BOUNDARY-001"],
    "mikrotik": ["LOG-001", "LOG-002", "MGMT-003", "BOUNDARY-001", "MGMT-005", "MGMT-009"],
    "fortios": ["MGMT-002", "LOG-002"],
}
# hardened settings that were read as a FAIL before: they must now be read, and pass
MUST_PASS = {"mikrotik": ["MGMT-009"], "huawei": ["LOG-002"], "fortios": ["LOG-002"]}


def _file(stem: str, kind: str) -> Path:
    return next(GAPS.glob(f"{stem}_{kind}.*"))


def _results(stem: str, kind: str) -> dict:
    path = _file(stem, kind)
    by_control: dict[str, list] = {}
    for r in run_scan([(path.name, path.read_text(encoding="utf-8"))]).results:
        by_control.setdefault(r.control_id, []).append(r)
    return by_control


def _backed(result) -> bool:
    """A cited line, or a reason that names the documented default (and its source) or how the dialect states the
    setting it found missing."""
    reason = result.reason
    return (bool(result.evidence.line_numbers) or " default, no line changes it: " in reason
            or "no line states it; " in reason.lower())


@pytest.mark.parametrize("stem,control", [(s, c) for s, checks in PLANTED.items() for c in checks])
def test_each_planted_problem_fails_with_evidence(seeded_adaptive_db, stem, control):
    results = _results(stem, "insecure").get(control, [])
    fails = [r for r in results if r.status == "fail"]
    assert fails, f"{control} on {stem}_insecure: {[(r.status, r.reason) for r in results]}"
    assert all(_backed(r) for r in fails), [(r.reason, r.evidence, r.facts) for r in fails]


@pytest.mark.parametrize("stem", list(PLANTED))
def test_the_hardened_file_fails_none_of_them(seeded_adaptive_db, stem):
    results = _results(stem, "hardened")
    fails = {c: [r.reason for r in results.get(c, []) if r.status == "fail"] for c in PLANTED[stem]}
    assert not any(fails.values()), {c: f for c, f in fails.items() if f}


@pytest.mark.parametrize("stem,control", [(s, c) for s, checks in MUST_PASS.items() for c in checks])
def test_hardened_settings_once_misread_now_pass(seeded_adaptive_db, stem, control):
    statuses = [r.status for r in _results(stem, "hardened").get(control, [])]
    assert statuses and set(statuses) == {"pass"}, statuses


def _scan(text: str) -> dict:
    by_control: dict[str, set] = {}
    for r in run_scan([("edge.cfg", text)]).results:
        by_control.setdefault(r.control_id, set()).add(r.status)
    return by_control


def _gap(name: str) -> str:
    return (GAPS / name).read_text(encoding="utf-8")


# Each default or new reading stands aside the moment a line may say otherwise: undecided, never a false alarm
EDGES = [
    # a VRP restriction outside the VTY view (``ssh server acl``) may be the one that applies
    ("huawei_insecure.cfg", " stelnet server enable", " stelnet server enable\n ssh server acl 2001", "MGMT-003",
     {"unknown"}),
    # a service line naming an address in a form the seeds do not read: the RouterOS default no longer applies
    ("mikrotik_insecure.rsc", "set telnet disabled=no", "set telnet address=10.0.0.0/8 disabled=no", "MGMT-003",
     {"unknown"}),
    # an HTTP API that is shut down serves nothing, whatever protocol it names
    ("arista_hardened.conf", "   protocol https\n   no shutdown", "   protocol http\n   shutdown", "MGMT-002",
     {"pass"}),
    # one unauthenticated NTP server can still set the clock
    ("fortios_hardened.conf", "        next\n    end\nend",
     '        next\n        edit 2\n            set server "192.0.2.124"\n        next\n    end\nend', "LOG-002", {"fail"}),
    # root may log in with a key only: not the password login this check is about, so it is not decided
    ("junos_set_insecure.conf", "root-login allow", "root-login deny-password", "AUTH-004", {"not_configured"}),
]


@pytest.mark.parametrize("name,old,new,control,expected", EDGES)
def test_a_line_that_may_say_otherwise_is_never_overruled(seeded_adaptive_db, name, old, new, control, expected):
    text = _gap(name)
    assert old in text
    assert _scan(text.replace(old, new, 1)).get(control) == expected


def test_a_log_line_that_keeps_logs_on_the_device_is_not_a_remote_destination(seeded_adaptive_db):
    # Junos ``syslog { file messages … }`` alone: the dialect states remote hosts as ``host …``, and none is there
    text = _gap("junos_hier_insecure.conf").replace("        host 192.0.2.50 {\n            any notice;\n        }\n", "")
    assert _scan(text).get("LOG-001") == {"fail"}
