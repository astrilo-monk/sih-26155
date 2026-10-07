"""
Phase: the resolution loop -initial scan → unresolved queue → teach → rescan → updated score.

Every test here asserts the loop moves a control from UNKNOWN / NOT_CONFIGURED to PASS / FAIL only
through evidence the uploaded configuration itself states, and that the scoring engine is untouched.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.analysis.scoring import calculate_posture, control_outcomes
from app.controls.catalog import CONTROLS
from app.facts.teaching import asserted_candidate, meanings, suggested_lines
from app.main import app

# The Junos configuration these tests are pinned to lives in tests/fixtures/: sample/ is the user's
# playground and its files change, while every number asserted here is a reading of one exact file.
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLES = Path(__file__).resolve().parents[2] / "sample"
JUNIPER_CFG = FIXTURES / "juniper_edge.cfg"
SOURCE_RESTRICTED = "mgmt.remote_access.source_restricted"
PROSE = (
    "Dear team,\n\n"
    "This is a note about our quarterly planning meeting. Please review the\n"
    "agenda before Thursday and let me know if you have questions.\n\n"
    "Thanks,\nAlex\n"
)


# Read cleanly by the Cisco parser, but silent on source routing and SSH version: the parser
# understood every line and there is nothing to teach -the device simply lacks the settings.
CISCO_MISSING_SETTINGS = """hostname EDGE-01
service password-encryption
enable secret 5 $1$abc$xyz
no ip http server
line vty 0 4
 transport input ssh
 exec-timeout 10 0
!
end
"""


@pytest.fixture
def client(seeded_adaptive_db):
    """A client on a fresh deployment: the shipped seed recognizers are loaded, nothing else is."""
    return TestClient(app)


def upload(client, name: str, text: str) -> dict:
    response = client.post("/api/scan", files={"files": (name, io.BytesIO(text.encode()), "text/plain")})
    assert response.status_code == 200, response.text
    return response.json()


def juniper(client) -> tuple[dict, str]:
    text = JUNIPER_CFG.read_text(encoding="utf-8")
    scan = upload(client, "juniper.cfg", text)
    return scan, text


def unresolved(client, scan_id: str) -> dict:
    response = client.get(f"/api/adaptive/scans/{scan_id}/unresolved")
    assert response.status_code == 200, response.text
    return response.json()


# ── 1. the initial score is what it always was ───────────────────────────────

def test_initial_juniper_score_is_unchanged(client):
    scan, _ = juniper(client)
    # was (27, 24) before MGMT-010/011, AUTH-001…003, LOG-003, CRYPTO-002, BOUNDARY-004: 'user admin' is a decided AUTH-003
    # FAIL (posture 24), and more questions apply that this file does not answer. Was (24, 19) before learned absence:
    # Junos knowledge knows how an AAA server and a login banner are written and this file states neither -two FAILs.
    # Was (19, 24) before brace leaves were read by set-form seeds: the users' encrypted-password is a decided MGMT-005 PASS
    # Was (38, 32) before Junos knowledge learned how NTP authentication is written (``trusted-key``): the file names an
    # NTP server and no key, so LOG-002 is a decided FAIL
    # Was (36, 34) with 15 unresolved before MGMT-012, BOUNDARY-005/006, CRYPTO-003. No line names SNMPv3, so MGMT-012
    # is N/A; the file runs OSPF without authentication (BOUNDARY-006 undecided until a person teaches it), and
    # BOUNDARY-005 / CRYPTO-003 have no Junos knowledge yet
    assert (scan["posture"], scan["coverage"]) == (36, 32)
    assert scan["assessed_count"] == 8
    assert scan["unresolved_count"] == 18


def test_initial_score_comes_from_the_scoring_engine(client):
    """The response's counts and the posture are two readings of one calculation, never a second one."""
    scan, _ = juniper(client)
    results = scan["results"]
    controls = {r["control_id"] for r in results}
    # a check that does not apply (SNMPv3 on a device that never names it) is neither assessed nor unresolved
    not_applicable = {c for c in controls if all(r["status"] == "n_a" for r in results if r["control_id"] == c)}
    assert not_applicable == {"MGMT-012"}
    assert scan["assessed_count"] + scan["unresolved_count"] + len(not_applicable) == len(controls)


# ── 2-3. undecided controls become an actionable queue ───────────────────────

def test_unresolved_queue_lists_exactly_what_coverage_left_out(client):
    scan, _ = juniper(client)
    queue = unresolved(client, scan["scan_id"])
    assert queue["unresolved_count"] == scan["unresolved_count"] == len(queue["items"])
    assert queue["assessed_count"] == scan["assessed_count"]
    statuses = {item["status"] for item in queue["items"]}
    assert statuses <= {"unknown", "not_configured"}
    assert "unknown" in statuses and "not_configured" in statuses


def test_every_unresolved_item_says_why_and_what_to_do(client):
    scan, _ = juniper(client)
    for item in unresolved(client, scan["scan_id"])["items"]:
        assert item["reason"]
        assert item["question"]
        assert item["action"] in ("teach", "blocked")
        if item["action"] == "blocked":
            assert item["blocked_reason"]


def test_queue_offers_the_lines_it_has_and_claims_none_it_does_not(client):
    scan, _ = juniper(client)
    items = {i["control_id"]: i for i in unresolved(client, scan["scan_id"])["items"]}
    # syslog is configured, to local files only: the syslog lines are offered
    assert [line["line_number"] for line in items["LOG-001"]["suggested_lines"]]
    # nothing in this configuration mentions an idle timeout, and none is invented
    assert items["MGMT-006"]["suggested_lines"] == []


def test_a_read_dialect_is_told_what_to_do_instead_of_being_told_about_recognizers(client):
    """A confirmed vendor cannot be taught, but "recognizers do not apply here" answers a question the
    operator did not ask and reads as though the engine gave up. What it actually found is a setting
    the device does not have, and the queue has to say so."""
    scan = upload(client, "edge.cfg", CISCO_MISSING_SETTINGS)
    items = {i["control_id"]: i for i in unresolved(client, scan["scan_id"])["items"]}
    absent = items["BOUNDARY-002"]          # no 'ip source-route' line of either polarity

    assert absent["action"] == "blocked" and absent["suggested_lines"] == []
    assert "cisco_ios parser read this configuration" in absent["blocked_reason"]
    assert "configuring it and scanning again" in absent["blocked_reason"]
    # the old wording explained the teaching system rather than the device
    assert "recognizers are for configurations" not in absent["blocked_reason"]


# ── 4. opening an unresolved control ─────────────────────────────────────────

def test_config_lines_are_readable_for_picking_a_line(client):
    scan, text = juniper(client)
    body = client.get(f"/api/adaptive/scans/{scan['scan_id']}/configs/0/lines").json()
    assert len(body["lines"]) == len(text.splitlines())
    assert body["lines"][0]["text"] == "system {"
    assert any(line["teachable"] for line in body["lines"])


def test_meanings_offered_for_a_line_are_the_controls_settings(client):
    scan, _ = juniper(client)
    body = client.get(f"/api/adaptive/scans/{scan['scan_id']}/meanings",
                      params={"control_id": "MGMT-003", "line_number": 98}).json()
    assert {(o["predicate"], o["value"]) for o in body["options"]} == {
        (SOURCE_RESTRICTED, True), (SOURCE_RESTRICTED, False)}


# ── 5-11. teach → persist → rescan → updated score ───────────────────────────

def teach_mgmt_003(client, scan_id: str):
    request = {"config_index": 0, "control_id": "MGMT-003", "line_number": 98,
               "predicate": SOURCE_RESTRICTED, "asserted_value": True}
    draft = client.post(f"/api/adaptive/scans/{scan_id}/recognizers/draft", json=request)
    assert draft.status_code == 200, draft.text
    assert draft.json()["errors"] == []
    saved = client.post(f"/api/adaptive/scans/{scan_id}/recognizers", json=request)
    assert saved.status_code == 200, saved.text
    return saved.json()


def test_teaching_an_unfamiliar_line_resolves_its_control(client):
    scan, _ = juniper(client)
    saved = teach_mgmt_003(client, scan["scan_id"])
    after = saved["scan"]

    result = next(r for r in after["results"] if r["control_id"] == "MGMT-003")
    assert result["status"] in ("pass", "fail")
    assert result["assurance"] == "confirmed"
    # coverage rose, posture was recalculated, one fewer control needs input
    assert after["coverage"] > scan["coverage"]
    assert after["assessed_count"] == scan["assessed_count"] + 1
    assert after["unresolved_count"] == scan["unresolved_count"] - 1
    assert after["posture"] != scan["posture"]


def test_the_recognizer_is_persisted_and_reused_by_the_next_scan(client):
    scan, text = juniper(client)
    teach_mgmt_003(client, scan["scan_id"])

    stored = client.get("/api/adaptive/mappings").json()
    assert any(m["extraction_method"] == "recognizer" and m["predicate"] == SOURCE_RESTRICTED
               and m["confirmed"] for m in stored)

    # a brand new scan of the same configuration starts where the last one ended
    again = upload(client, "juniper.cfg", text)
    assert again["coverage"] > scan["coverage"]
    assert next(r for r in again["results"] if r["control_id"] == "MGMT-003")["status"] in ("pass", "fail")


def test_resolving_shrinks_the_queue(client):
    scan, _ = juniper(client)
    before = unresolved(client, scan["scan_id"])
    teach_mgmt_003(client, scan["scan_id"])
    after = unresolved(client, scan["scan_id"])
    assert after["unresolved_count"] == before["unresolved_count"] - 1
    assert "MGMT-003" not in {i["control_id"] for i in after["items"]}


def test_the_uploaded_configuration_is_never_changed(client):
    scan, text = juniper(client)
    listing = f"/api/adaptive/scans/{scan['scan_id']}/configs/0/lines"
    before = client.get(listing).json()["lines"]
    teach_mgmt_003(client, scan["scan_id"])
    assert client.get(listing).json()["lines"] == before
    # and what is served is the uploaded file itself, only with its secrets blanked for display
    assert len(before) == len(text.splitlines())
    assert [line["text"] for line in before if "password" not in line["text"]] ==         [line for line in text.splitlines() if "password" not in line]


# ── 12-13. an answer that the line does not support is refused ───────────────

def test_a_line_that_states_no_value_cannot_teach_one(client):
    """`server 192.168.10.10;` names an NTP server and says nothing about authenticating it."""
    scan, _ = juniper(client)
    request = {"config_index": 0, "control_id": "LOG-002", "line_number": 51,
               "predicate": "time.ntp.authenticated", "asserted_value": True}
    draft = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers/draft", json=request).json()
    assert draft["errors"], "a line stating no polarity must not pass the gates"
    refused = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers", json=request)
    assert refused.status_code == 422
    # and the control is still exactly where it was: a FAIL read from absence (no line states a trusted key)
    log = next(r for r in scan["results"] if r["control_id"] == "LOG-002")
    assert log["status"] == "fail"
    after = unresolved(client, scan["scan_id"])
    assert "LOG-002" not in {i["control_id"] for i in after["items"]}


def test_a_predicate_the_control_does_not_read_is_refused(client):
    scan, _ = juniper(client)
    response = client.post(f"/api/adaptive/scans/{scan['scan_id']}/recognizers/draft", json={
        "config_index": 0, "control_id": "MGMT-003", "line_number": 98,
        "predicate": "banner.login.present", "asserted_value": True})
    assert response.status_code == 422


def test_undecided_controls_are_never_counted_as_passed_or_failed(client):
    scan, _ = juniper(client)
    undecided = {i["control_id"] for i in unresolved(client, scan["scan_id"])["items"]}
    decided = {r["control_id"] for r in scan["results"] if r["status"] in ("pass", "fail")}
    assert undecided & decided == set()
    # the posture is computed over the decided controls alone
    assert scan["posture"] == 36 and len(decided) == 8


# ── 14-15. the rest of the product is unaffected ─────────────────────────────

@pytest.mark.parametrize("name", ["cisco_vulnerable.cfg", "fortinet_vulnerable.cfg"])
def test_confirmed_vendor_scans_still_score(client, name):
    scan = upload(client, name, (FIXTURES / name).read_text(encoding="utf-8"))
    assert scan["posture"] is not None
    assert scan["coverage"] > 0
    assert scan["unreadable_configs"] == []
    for item in unresolved(client, scan["scan_id"])["items"]:
        # a dedicated parser reads this device: a recognizer would not be honest here
        assert item["action"] == "blocked"


# ── 16. a file that is not a configuration ───────────────────────────────────

def test_prose_is_reported_unreadable_and_never_scored(client):
    scan = upload(client, "notes.txt", PROSE)
    assert scan["unreadable_configs"] == [0]
    assert scan["posture"] is None
    assert scan["coverage"] == 0
    assert scan["assessed_count"] == 0


def test_a_real_configuration_is_never_called_unreadable(client):
    for path in (JUNIPER_CFG, SAMPLES / "unknown.cfg", SAMPLES / "paloalto.cfg",
                 FIXTURES / "cisco_vulnerable.cfg"):
        scan = upload(client, path.name, path.read_text(encoding="utf-8"))
        assert scan["unreadable_configs"] == [], path.name


# ── the units the queue is built from ────────────────────────────────────────

def test_control_outcomes_agree_with_the_posture(seeded_adaptive_db):
    from app.api.routes.scan import _process_unknown_vendor
    from app.analysis.engine import evaluate_controls

    config = _process_unknown_vendor(JUNIPER_CFG.read_text(encoding="utf-8"), "j.cfg")
    results = evaluate_controls(config)
    outcomes = control_outcomes([results])
    posture = calculate_posture([results])
    assert posture.coverage == 32
    assert sum(1 for o in outcomes.values() if o == "undecided") == 18
    assert set(posture.critical_unassessed) <= {c for (_, c), o in outcomes.items() if o == "undecided"}


def test_asserted_candidate_refuses_a_line_that_is_not_a_statement():
    lines = JUNIPER_CFG.read_text(encoding="utf-8").splitlines()
    with pytest.raises(LookupError):
        asserted_candidate(lines, CONTROLS["MGMT-003"], 54, SOURCE_RESTRICTED, True)


def test_suggested_lines_only_offer_lines_the_configuration_holds():
    lines = JUNIPER_CFG.read_text(encoding="utf-8").splitlines()
    for control in CONTROLS.values():
        for number, _ in suggested_lines(lines, control):
            assert 1 <= number <= len(lines)


def test_meanings_for_a_value_setting_do_not_state_the_value():
    lines = JUNIPER_CFG.read_text(encoding="utf-8").splitlines()
    options = meanings(lines, CONTROLS["LOG-001"], 44)
    assert options and all(o["value"] is None for o in options)
