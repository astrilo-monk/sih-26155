"""
Candidate remediation for unconfirmed vendors: proposed, deterministically checked, human-confirmed.

The invariants these tests pin:

* a candidate exists only for a **decisive** FAIL on an **unconfirmed** vendor -a confirmed vendor keeps
  the deterministic recipe path, and a provisional (heuristic / AI) verdict gets no candidate at all;
* command text -typed or AI-generated -is never executed, never applied to the stored configuration and
  never enters a download; the uploaded text, the scan results, posture and coverage do not move;
* "verified" means the command removes the finding from a **copy** of the configuration file, checked by
  re-reading it with the generic engine; it never means PASS-from-absence and never means the device changed;
* a command whose effect cannot be derived stays UNVERIFIED, one that does not resolve the finding is
  REJECTED, and nothing reaches an accepted state without a human confirming it;
* the AI sees no secrets, its answer is refused unless it is exactly the expected shape, and it decides nothing.

No vendor grammar is involved: the engine reads the configuration and the proposed text with the same
generic tokenizer for every dialect.
"""

import pathlib
import re

import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch

from app.adaptive.matcher import EXTRACTION_RECOGNIZER
from app.ai import remediation as ai_rem
from app.ai.client import ERROR_UNAVAILABLE, StructuredResponse
from app.api.routes.scan import get_scan_store
from app.controls.catalog import CONTROLS
from app.db.mappings import LearnedMapping, MappingRepository
from app.facts.recognizers import RECOGNIZER_PREDICATES, draft_recognizer
from app.main import app
from app.remediation import candidates as cand
from app.remediation.engine import analyze_generic_text

TESTS = pathlib.Path(__file__).parent
FIXTURES = TESTS / "fixtures"
SAMPLES = TESTS.parent.parent / "sample"
# The Junos configuration these tests are pinned to lives in tests/fixtures/: sample/ is the user's
# playground and its files change, while every number asserted here is a reading of one exact file.
JUNIPER_CFG = TESTS / "fixtures" / "juniper_edge.cfg"
JUNIPER = JUNIPER_CFG.read_text()

# A second, heuristic-only Telnet statement: removing the confirmed one does not resolve the finding
TWO_TELNETS = """system {
    services {
        telnet;
    }
}
management {
    telnet enable;
}
"""

SECRETS = """system {
    host-name EDGE-9;
    root-authentication {
        encrypted-password "$9$SuperSecretHash";
    }
    login {
        user netops {
            authentication {
                plain-text-password TopSecret123;
            }
        }
    }
    services {
        telnet;
    }
}
snmp {
    community PublicSecretCommunity {
        authorization read-only;
    }
}
"""


def _teach(text: str, line: int) -> None:
    """Confirm one recognizer for the statement on that line (what the Teach page does)."""
    fields = draft_recognizer(text.splitlines(), RECOGNIZER_PREDICATES, line)
    MappingRepository().save_mapping(LearnedMapping(
        concept="taught", normalized_field="", extraction_method=EXTRACTION_RECOGNIZER, confirmed=True, **fields))


def _line_of(text: str, statement: str) -> int:
    return next(i + 1 for i, line in enumerate(text.splitlines()) if line.strip() == statement)


def _scan(client: TestClient, name: str, text: str) -> dict:
    with patch("app.api.routes.scan.interpret_lines", MagicMock(return_value=[])), \
         patch("app.api.routes.scan.is_available", return_value=False):
        response = client.post("/api/scan", files=[("files", (name, text.encode(), "text/plain"))])
    assert response.status_code == 200, response.text
    return response.json()


def _taught_juniper_scan(client: TestClient) -> tuple[dict, dict]:
    """A Juniper-syntax scan whose Telnet and HTTP lines an administrator already confirmed."""
    _teach(JUNIPER, _line_of(JUNIPER, "telnet;"))
    _teach(JUNIPER, _line_of(JUNIPER, "http;"))
    scan = _scan(client, "juniper.cfg", JUNIPER)
    body = {"scan_id": scan["scan_id"], "rule_id": "MGMT-001",
            "device_hostname": scan["devices"][0]["hostname"], "config_index": 0}
    return scan, body


def _ai_answer(command: str, control_id: str = "MGMT-001", **overrides) -> StructuredResponse:
    data = {"control_id": control_id, "candidate_command": command,
            "explanation": "Removes the Telnet service from the system services hierarchy.",
            "confidence": "medium", "assumptions": ["a curly-brace hierarchical CLI"]}
    data.update(overrides)
    return StructuredResponse(data=data)


# ── the engine: what a candidate may and may not establish ──────────────────

def test_a_taught_unknown_vendor_finding_is_decisive_and_gets_no_deterministic_recipe():
    """The starting point: an honest 'unknown' vendor, a decisive FAIL, and no vendor commands."""
    _teach(JUNIPER, _line_of(JUNIPER, "telnet;"))
    analysis = analyze_generic_text(JUNIPER)
    assert not analysis.identification.confirmed
    fail = next(r for r in analysis.control("MGMT-001") if r.status.value == "fail")
    assert fail.assurance.value == "confirmed" and fail.evidence.line_numbers == [_line_of(JUNIPER, "telnet;")]
    assert cand.failing_evidence(analysis, "MGMT-001") == [(fail.evidence.line_numbers[0], fail.evidence.text[0])]


def test_a_negating_command_is_simulated_on_a_copy_and_leaves_the_original_untouched():
    _teach(JUNIPER, _line_of(JUNIPER, "telnet;"))
    original = JUNIPER
    item = cand.new_candidate(original, 0, "MGMT-001", cand.SOURCE_MANUAL, "delete system services telnet;")
    assert item.status == cand.CandidateStatus.DRAFT and item.control_status_before == "fail"

    cand.verify(item, original)
    assert item.status == cand.CandidateStatus.VERIFIED
    # the finding is gone; absence is NOT_CONFIGURED, never a PASS
    assert item.control_status_after == "not_configured"
    assert all(c.passed for c in item.checks)
    assert "-        telnet;" in item.diff
    # the configuration the scan holds is byte-identical: the simulation ran on a copy
    assert original == JUNIPER == JUNIPER_CFG.read_text()
    assert cand.apply_to_copy(original, [3]) != original and original == JUNIPER


def test_a_candidate_that_does_not_resolve_the_finding_is_rejected_and_never_passes_the_control():
    _teach(TWO_TELNETS, 3)
    item = cand.new_candidate(TWO_TELNETS, 0, "MGMT-001", cand.SOURCE_MANUAL, "delete system services telnet;")
    cand.verify(item, TWO_TELNETS)

    assert item.status == cand.CandidateStatus.REJECTED
    assert item.control_status_after == "fail"
    assert not next(c for c in item.checks if c.name == "target").passed
    assert "pass" not in (item.control_status_after or "")


@pytest.mark.parametrize("command", [
    "please turn off the web server",                    # not a command at all
    "set system services telnet;",                       # states the setting, does not remove it
    "delete system services ftp;",                        # a different setting
    "delete telnet;",                                     # does not name the block the statement lives in
    "delete system services telnet;\nrequest system reboot",  # also does something that cannot be checked
    "delete system services telnet;\nrm -rf /",           # dangerous text: still only ever text
])
def test_a_candidate_whose_effect_cannot_be_derived_stays_unverified(command):
    _teach(JUNIPER, _line_of(JUNIPER, "telnet;"))
    item = cand.new_candidate(JUNIPER, 0, "MGMT-001", cand.SOURCE_MANUAL, command)
    cand.verify(item, JUNIPER)

    assert item.status == cand.CandidateStatus.UNVERIFIED
    assert item.diff == "" and item.checks == [] and item.control_status_after is None
    assert "could not be verified automatically" in item.reason


def test_a_candidate_for_one_control_cannot_resolve_another():
    _teach(JUNIPER, _line_of(JUNIPER, "telnet;"))
    _teach(JUNIPER, _line_of(JUNIPER, "http;"))
    item = cand.new_candidate(JUNIPER, 0, "MGMT-002", cand.SOURCE_MANUAL, "delete system services telnet;")
    cand.verify(item, JUNIPER)

    # the command does not address MGMT-002's cited line, so nothing is simulated and nothing changes
    assert item.status == cand.CandidateStatus.UNVERIFIED
    assert analyze_generic_text(JUNIPER).control("MGMT-002")[0].status.value == "fail"


@pytest.mark.parametrize("command, message", [
    ("", "Enter the command"),
    ("   \n  ", "Enter the command"),
    ("x" * (cand.MAX_COMMAND_CHARS + 1), "at most"),
    ("\n".join(["delete a b"] * (cand.MAX_COMMAND_LINES + 1)), "at most"),
    ("delete a b\x00c", "control characters"),
    (None, "must be text"),
])
def test_unusable_command_text_is_refused_outright(command, message):
    with pytest.raises(cand.CandidateError) as e:
        cand.clean_command(command)
    assert message in str(e.value)


def test_confirmation_is_the_only_way_a_candidate_becomes_accepted():
    _teach(JUNIPER, _line_of(JUNIPER, "telnet;"))
    item = cand.new_candidate(JUNIPER, 0, "MGMT-001", cand.SOURCE_AI, "delete system services telnet;")
    cand.verify(item, JUNIPER)
    assert item.confirmed_at is None

    cand.confirm(item)
    assert item.status == cand.CandidateStatus.CONFIRMED and item.confirmed_at
    assert "has not connected to the device" in item.reason
    cand.reject(item, "we use a jump host instead")
    assert item.status == cand.CandidateStatus.REJECTED and item.confirmed_at is None
    assert "jump host" in item.reason


# ── API ──────────────────────────────────────────────────────────────────────

def test_api_manual_candidate_is_a_draft_then_verifies_then_confirms_without_moving_the_scan():
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)
    assert scan["vendor_identification"][0]["status"] == "unknown"
    assert any(f["rule_id"] == "MGMT-001" and f["assurance"] == "confirmed" for f in scan["findings"])

    plan = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    assert {r["rule_id"]: r["status"] for r in plan["remediations"]}["MGMT-001"] == "vendor_unverified"
    assert plan["candidates"] == [] and plan["fixed_config"] is None

    draft = client.post("/api/remediation/candidate", json={**body, "command": "delete system services telnet;"})
    assert draft.status_code == 200, draft.text
    assert draft.json()["status"] == "draft" and draft.json()["source"] == "manual"
    assert draft.json()["evidence"]["line_numbers"] == [_line_of(JUNIPER, "telnet;")]

    # a draft has not been checked: it cannot be confirmed
    assert client.post("/api/remediation/candidate/confirm", json=body).status_code == 409

    verified = client.post("/api/remediation/candidate/verify", json=body).json()
    assert verified["status"] == "verified"
    assert (verified["control_status_before"], verified["control_status_after"]) == ("fail", "not_configured")
    assert {c["name"]: c["passed"] for c in verified["checks"]} == {
        "target": True, "no_regression": True, "generic_path": True}
    assert "not establish that the command is safe to run on the physical device" in verified["reason"]

    confirmed = client.post("/api/remediation/candidate/confirm", json=body).json()
    assert confirmed["status"] == "confirmed" and confirmed["confirmed_at"]

    # nothing about the audit moved: the device has not been changed, so the problem is still a problem
    after = client.get(f"/api/scan/{scan['scan_id']}").json()
    for field in ("posture", "coverage", "critical_unassessed", "total_findings"):
        assert after[field] == scan[field]
    assert [(r["control_id"], r["status"], r["assurance"]) for r in after["results"]] == \
           [(r["control_id"], r["status"], r["assurance"]) for r in scan["results"]]
    assert client.post("/api/download-fixed", json={"scan_id": scan["scan_id"]}).status_code == 409
    # the stored configuration text is untouched
    assert get_scan_store()[scan["scan_id"]]["configs"][0].raw_config == JUNIPER
    # and the plan now carries the candidate, so a reload keeps it
    reloaded = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    assert [(c["rule_id"], c["status"]) for c in reloaded["candidates"]] == [("MGMT-001", "confirmed")]


def test_api_ai_candidate_is_labelled_unverified_and_decides_nothing():
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)
    with patch.object(ai_rem, "request_structured", return_value=_ai_answer("delete system services telnet;")), \
         patch("app.api.routes.remediation.is_available", return_value=True):
        generated = client.post("/api/remediation/candidate/generate", json=body)
    assert generated.status_code == 200, generated.text
    item = generated.json()

    assert item["source"] == "ai" and item["status"] == "draft"
    assert item["command"] == "delete system services telnet;" and item["confidence"] == "medium"
    assert item["assumptions"] == ["a curly-brace hierarchical CLI"]
    assert item["control_status_after"] is None and item["checks"] == [] and item["diff"] == ""

    # the AI answer alone changed no result, no finding and no posture
    after = client.get(f"/api/scan/{scan['scan_id']}").json()
    assert (after["posture"], after["coverage"], after["total_findings"]) == \
           (scan["posture"], scan["coverage"], scan["total_findings"])
    assert next(r for r in after["results"] if r["control_id"] == "MGMT-001")["status"] == "fail"

    # it becomes a checked candidate only through the same verification as a typed command
    verified = client.post("/api/remediation/candidate/verify", json=body).json()
    assert verified["status"] == "verified" and verified["source"] == "ai"


def test_api_ai_is_never_asked_for_a_confirmed_vendor_and_the_deterministic_path_is_unchanged():
    client = TestClient(app)
    scan = _scan(client, "cisco.cfg", (FIXTURES / "cisco_vulnerable.cfg").read_text())
    body = {"scan_id": scan["scan_id"], "rule_id": "MGMT-001", "device_hostname": "CORP-RTR-01", "config_index": 0}

    for path in ("", "/generate", "/verify", "/confirm", "/reject"):
        response = client.post(f"/api/remediation/candidate{path}",
                               json={**body, "command": "no transport input telnet"})
        assert response.status_code == 409, path
        assert "vendor is confirmed" in response.json()["detail"]

    # the recipe path still works exactly as before
    fixed = client.post("/api/remediate", json=body).json()
    assert fixed["status"] == "fixed" and fixed["control_status_after"] == "pass"
    plan = client.post("/api/remediation/plan", json={"scan_id": scan["scan_id"]}).json()["devices"][0]
    assert plan["candidates"] == [] and plan["fixed_config"] and plan["fixed_controls"]


def test_api_a_provisional_finding_gets_no_candidate():
    """A heuristic verdict is not evidence for remediation -candidate or deterministic."""
    client = TestClient(app)
    scan = _scan(client, "unknown.cfg", (SAMPLES / "unknown.cfg").read_text())
    assert any(f["rule_id"] == "MGMT-001" and f["assurance"] == "heuristic" for f in scan["findings"])
    body = {"scan_id": scan["scan_id"], "rule_id": "MGMT-001",
            "device_hostname": scan["devices"][0]["hostname"], "config_index": 0}

    response = client.post("/api/remediation/candidate", json={**body, "command": "no telnet"})
    assert response.status_code == 409 and "confirmed failure" in response.json()["detail"]


def test_api_rejecting_a_candidate_changes_nothing():
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)
    client.post("/api/remediation/candidate", json={**body, "command": "delete system services telnet;"})
    client.post("/api/remediation/candidate/verify", json=body)

    rejected = client.post("/api/remediation/candidate/reject", json={**body, "reason": "we disable the port instead"})
    assert rejected.status_code == 200 and rejected.json()["status"] == "rejected"
    assert "we disable the port instead" in rejected.json()["reason"]
    assert client.post("/api/remediation/candidate/confirm", json=body).status_code == 409

    after = client.get(f"/api/scan/{scan['scan_id']}").json()
    assert (after["posture"], after["coverage"], after["total_findings"]) == \
           (scan["posture"], scan["coverage"], scan["total_findings"])
    assert get_scan_store()[scan["scan_id"]]["configs"][0].raw_config == JUNIPER
    assert client.post("/api/download-fixed", json={"scan_id": scan["scan_id"]}).status_code == 409


def test_api_unknown_control_device_and_missing_candidate_are_refused():
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)
    assert client.post("/api/remediation/candidate", json={**body, "rule_id": "NOPE-1", "command": "x y"}).status_code == 404
    assert client.post("/api/remediation/candidate",
                       json={**body, "device_hostname": "OTHER", "config_index": 0, "command": "x y"}).status_code == 404
    assert client.post("/api/remediation/candidate/verify", json=body).status_code == 404
    assert client.post("/api/remediation/candidate", json={**body, "command": "  "}).status_code == 422


def test_api_generation_failures_are_reported_and_never_invented():
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)

    with patch("app.api.routes.remediation.is_available", return_value=False):
        unavailable = client.post("/api/remediation/candidate/generate", json=body)
    assert unavailable.status_code == 503 and "AI is not configured" in unavailable.json()["detail"]

    with patch.object(ai_rem, "request_structured", return_value=StructuredResponse(error=ERROR_UNAVAILABLE)), \
         patch("app.api.routes.remediation.is_available", return_value=True):
        failed = client.post("/api/remediation/candidate/generate", json=body)
    assert failed.status_code == 503 and "No candidate could be generated" in failed.json()["detail"]
    # nothing was recorded, so there is nothing to verify or confirm
    assert client.post("/api/remediation/candidate/verify", json=body).status_code == 404


# ── AI safety: redaction and answer shape ───────────────────────────────────

def test_no_secret_reaches_the_ai_remediation_prompt():
    client = TestClient(app)
    _teach(SECRETS, _line_of(SECRETS, "telnet;"))
    scan = _scan(client, "secrets.cfg", SECRETS)
    body = {"scan_id": scan["scan_id"], "rule_id": "MGMT-001",
            "device_hostname": scan["devices"][0]["hostname"], "config_index": 0}
    seen = {}

    def capture(**kwargs):
        seen.update(kwargs)
        return _ai_answer("delete system services telnet;")

    with patch.object(ai_rem, "request_structured", side_effect=capture), \
         patch("app.api.routes.remediation.is_available", return_value=True):
        response = client.post("/api/remediation/candidate/generate", json=body)
    assert response.status_code == 200, response.text

    sent = seen["prompt"] + seen["system_instruction"]
    for secret in ("$9$SuperSecretHash", "TopSecret123", "PublicSecretCommunity"):
        assert secret not in sent
    assert "telnet" in sent and "MGMT-001" in sent
    # and no secret is echoed back to the browser either
    assert not any(s in response.text for s in ("$9$SuperSecretHash", "TopSecret123", "PublicSecretCommunity"))


def test_an_ai_answer_that_is_not_exactly_the_expected_shape_is_refused():
    control = CONTROLS["MGMT-001"]
    good = {"control_id": "MGMT-001", "candidate_command": "delete system services telnet;",
            "explanation": "ok", "confidence": "high", "assumptions": []}
    assert ai_rem._validated(good, "MGMT-001")[0].command == "delete system services telnet;"

    for bad in (
        {**good, "extra": "run this"},                      # a field the contract does not have
        {k: v for k, v in good.items() if k != "explanation"},  # a missing field
        {**good, "control_id": "MGMT-002"},                 # an answer about another control
        {**good, "candidate_command": ""},                  # no command
        {**good, "candidate_command": 42},                  # not text
        {**good, "confidence": "certain"},                  # not one of the three levels
        {**good, "assumptions": "a string"},                # not a list
        {**good, "assumptions": [{"why": "x"}]},            # not a list of text
        {**good, "explanation": None},
        "delete system services telnet;",                   # not an object at all
        None,
    ):
        proposal, detail = ai_rem._validated(bad, "MGMT-001")
        assert proposal is None and detail

    # and the route refuses such an answer rather than repairing it
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)
    with patch.object(ai_rem, "request_structured", return_value=_ai_answer("x", control_id="MGMT-009")), \
         patch("app.api.routes.remediation.is_available", return_value=True):
        response = client.post("/api/remediation/candidate/generate", json=body)
    assert response.status_code == 503 and "MGMT-009" in response.json()["detail"]
    assert control.control_id == "MGMT-001"


def test_a_dangerous_ai_command_is_kept_as_text_and_never_verified():
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)
    dangerous = "delete system services telnet;\nrequest system zeroize\nrm -rf /"
    with patch.object(ai_rem, "request_structured", return_value=_ai_answer(dangerous)), \
         patch("app.api.routes.remediation.is_available", return_value=True):
        item = client.post("/api/remediation/candidate/generate", json=body).json()
    assert item["status"] == "draft"

    verified = client.post("/api/remediation/candidate/verify", json=body).json()
    assert verified["status"] == "unverified" and verified["diff"] == ""
    assert get_scan_store()[scan["scan_id"]]["configs"][0].raw_config == JUNIPER
    # the only thing that ever happens to command text is that it is stored and shown
    source = (pathlib.Path(cand.__file__).read_text() + pathlib.Path(ai_rem.__file__).read_text())
    assert not re.search(r"subprocess|os\.system|popen|paramiko|\beval\(|\bexec\(", source, re.I)


def test_the_candidate_engine_names_no_vendor():
    """Generic by construction: no dialect table, no vendor branch, no parser selection."""
    source = (pathlib.Path(cand.__file__).read_text() + pathlib.Path(ai_rem.__file__).read_text())
    for vendor in ("juniper", "junos", "palo", "panos", "mikrotik", "arista", "huawei", "fortigate", "fortinet",
                   "cisco", "ios"):
        assert not re.search(rf"\b{vendor}\b", source, re.I), vendor



# ── the verified corrected copy ─────────────────────────────────────────────
# A verified candidate keeps the edited COPY it was verified against, so an administrator can download
# it. It is the uploaded file with that one simulated change -never a device configuration NetAuditAI
# generated, never something applied anywhere, and never reachable from any other candidate state.

def _download(client: TestClient, body: dict):
    return client.post("/api/remediation/candidate/download", json=body)


def test_verification_retains_exactly_the_text_it_verified_and_nothing_else_does():
    _teach(JUNIPER, _line_of(JUNIPER, "telnet;"))
    item = cand.new_candidate(JUNIPER, 0, "MGMT-001", cand.SOURCE_MANUAL, "delete system services telnet;")
    assert item.verified_config is None and not cand.downloadable(item)  # a draft has nothing

    cand.verify(item, JUNIPER)
    assert item.status == cand.CandidateStatus.VERIFIED and cand.downloadable(item)
    # exactly the simulated result: the uploaded text minus the cited line, nothing else touched
    expected = cand.apply_to_copy(JUNIPER, [_line_of(JUNIPER, "telnet;")])
    assert item.verified_config == expected
    assert not any(line.strip() == "telnet;" for line in item.verified_config.splitlines())
    assert "host-name JUNIPER-EDGE-01;" in item.verified_config and "ftp;" in item.verified_config
    # and re-reading that copy is what the checks were made of
    assert analyze_generic_text(item.verified_config).control("MGMT-001")[0].status.value == "not_configured"
    # the uploaded configuration is untouched on disk and in memory
    assert JUNIPER == JUNIPER_CFG.read_text()

    # confirmation keeps it; rejection takes it away
    cand.confirm(item)
    assert cand.downloadable(item) and item.verified_config == expected
    cand.reject(item)
    assert item.verified_config is None and not cand.downloadable(item)


def test_a_candidate_that_fails_or_cannot_be_checked_retains_no_downloadable_copy():
    _teach(TWO_TELNETS, 3)
    rejected = cand.new_candidate(TWO_TELNETS, 0, "MGMT-001", cand.SOURCE_MANUAL, "delete system services telnet;")
    cand.verify(rejected, TWO_TELNETS)
    assert rejected.status == cand.CandidateStatus.REJECTED
    assert rejected.verified_config is None and not cand.downloadable(rejected)

    # the same taught statement decides JUNIPER's Telnet line too
    unverified = cand.new_candidate(JUNIPER, 0, "MGMT-001", cand.SOURCE_MANUAL, "please turn off telnet")
    cand.verify(unverified, JUNIPER)
    assert unverified.status == cand.CandidateStatus.UNVERIFIED and not cand.downloadable(unverified)
    # confirming a command NetAuditAI could not check still gives nothing to download
    cand.confirm(unverified)
    assert unverified.status == cand.CandidateStatus.CONFIRMED and not cand.downloadable(unverified)


def test_re_verifying_against_a_configuration_it_no_longer_fits_drops_the_copy():
    """The copy never outlives the check that produced it."""
    _teach(JUNIPER, _line_of(JUNIPER, "telnet;"))
    item = cand.new_candidate(JUNIPER, 0, "MGMT-001", cand.SOURCE_MANUAL, "delete system services telnet;")
    cand.verify(item, JUNIPER)
    assert cand.downloadable(item)

    # the same recognizer decides both Telnet statements of TWO_TELNETS, so the command no longer suffices
    cand.verify(item, TWO_TELNETS)
    assert item.status == cand.CandidateStatus.REJECTED and item.verified_config is None


def test_api_only_a_verified_candidate_can_be_downloaded():
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)
    telnet_line = _line_of(JUNIPER, "telnet;")

    # no candidate at all
    assert _download(client, body).status_code == 404

    draft = client.post("/api/remediation/candidate", json={**body, "command": "delete system services telnet;"}).json()
    assert draft["download_available"] is False
    refused = _download(client, body)
    assert refused.status_code == 409 and "no verified corrected copy" in refused.json()["detail"]

    verified = client.post("/api/remediation/candidate/verify", json=body).json()
    assert verified["status"] == "verified" and verified["download_available"] is True
    # the browser is told a file exists; the configuration text itself is not in the JSON
    assert "verified_config" not in verified

    response = _download(client, body)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["content-disposition"] == \
        'attachment; filename="JUNIPER-EDGE-01_MGMT-001_verified_copy.cfg"'
    assert "not applied to any device" in response.headers["x-netauditai-note"]

    downloaded = response.text
    assert downloaded == cand.apply_to_copy(JUNIPER, [telnet_line])
    assert not any(line.strip() == "telnet;" for line in downloaded.splitlines())
    assert "ftp;" in downloaded and "host-name JUNIPER-EDGE-01;" in downloaded

    # confirming keeps it downloadable and byte-identical
    client.post("/api/remediation/candidate/confirm", json=body)
    assert _download(client, body).text == downloaded

    # and downloading changed nothing: not the stored file, not the results, not the posture
    assert get_scan_store()[scan["scan_id"]]["configs"][0].raw_config == JUNIPER
    assert JUNIPER == JUNIPER_CFG.read_text()
    after = client.get(f"/api/scan/{scan['scan_id']}").json()
    for field in ("posture", "coverage", "critical_unassessed", "total_findings"):
        assert after[field] == scan[field]
    assert [(r["control_id"], r["status"]) for r in after["results"]] == \
           [(r["control_id"], r["status"]) for r in scan["results"]]
    # /download-fixed is still confirmed-vendor only: the candidate copy never leaks into it
    assert client.post("/api/download-fixed", json={"scan_id": scan["scan_id"]}).status_code == 409


def test_api_a_rejected_candidate_cannot_be_downloaded():
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)
    client.post("/api/remediation/candidate", json={**body, "command": "delete system services telnet;"})
    client.post("/api/remediation/candidate/verify", json=body)
    assert _download(client, body).status_code == 200

    client.post("/api/remediation/candidate/reject", json=body)
    refused = _download(client, body)
    assert refused.status_code == 409 and "'rejected'" in refused.json()["detail"]


def test_api_an_ai_candidate_is_downloadable_only_after_deterministic_verification():
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)
    with patch.object(ai_rem, "request_structured", return_value=_ai_answer("delete system services telnet;")), \
         patch("app.api.routes.remediation.is_available", return_value=True):
        generated = client.post("/api/remediation/candidate/generate", json=body).json()
    assert generated["source"] == "ai" and generated["download_available"] is False
    assert _download(client, body).status_code == 409

    verified = client.post("/api/remediation/candidate/verify", json=body).json()
    assert verified["download_available"] is True
    assert _download(client, body).text == cand.apply_to_copy(JUNIPER, [_line_of(JUNIPER, "telnet;")])


def test_api_each_candidate_gets_its_own_copy_and_they_are_never_combined():
    """One verified corrected copy per candidate: MGMT-002's copy still contains MGMT-001's problem."""
    client = TestClient(app)
    scan, telnet = _taught_juniper_scan(client)
    client.post("/api/remediation/candidate", json={**telnet, "command": "delete system services telnet;"})
    client.post("/api/remediation/candidate/verify", json=telnet)

    http = {**telnet, "rule_id": "MGMT-002"}
    draft = client.post("/api/remediation/candidate",
                        json={**http, "command": "delete system services web-management http;"})
    assert draft.status_code == 200, draft.text
    verified = client.post("/api/remediation/candidate/verify", json=http).json()
    assert verified["status"] == "verified" and verified["download_available"] is True

    telnet_copy = _download(client, telnet).text
    http_copy = _download(client, http).text
    assert telnet_copy == cand.apply_to_copy(JUNIPER, [_line_of(JUNIPER, "telnet;")])
    assert http_copy == cand.apply_to_copy(JUNIPER, [_line_of(JUNIPER, "http;")])
    # neither copy silently carries the other candidate's change
    assert any(line.strip() == "telnet;" for line in http_copy.splitlines())
    assert any(line.strip() == "http;" for line in telnet_copy.splitlines())
    assert _download(client, http).headers["content-disposition"].endswith('MGMT-002_verified_copy.cfg"')


def test_api_the_verified_copy_lives_only_in_scan_memory():
    client = TestClient(app)
    scan, body = _taught_juniper_scan(client)
    client.post("/api/remediation/candidate", json={**body, "command": "delete system services telnet;"})
    client.post("/api/remediation/candidate/verify", json=body)
    copy = _download(client, body).text

    # never written to the learned-mappings database
    from app.config import settings
    assert copy not in settings.adaptive_db_path.read_bytes().decode("utf-8", "replace")

    # and it lives no longer than the scan that produced it
    get_scan_store().pop(scan["scan_id"])
    # the archived scan keeps its results, never the copy: acting on it asks for the configuration again
    assert _download(client, body).status_code == 409


def test_api_a_confirmed_vendor_has_no_candidate_download():
    """The unconfirmed-vendor path is separate: it cannot be used to reach a confirmed vendor's file."""
    client = TestClient(app)
    scan = _scan(client, "cisco.cfg", (FIXTURES / "cisco_vulnerable.cfg").read_text())
    body = {"scan_id": scan["scan_id"], "rule_id": "MGMT-001", "device_hostname": "CORP-RTR-01", "config_index": 0}
    response = _download(client, body)
    assert response.status_code == 409 and "vendor is confirmed" in response.json()["detail"]
    # the confirmed path still hands out its own, separately generated file
    assert client.post("/api/download-fixed", json={"scan_id": scan["scan_id"]}).status_code == 200


def test_the_verified_copy_is_the_uploaded_file_and_reaches_no_device():
    """It holds exactly what was uploaded, and nothing in this path can talk to a device."""
    client = TestClient(app)
    _teach(SECRETS, _line_of(SECRETS, "telnet;"))
    scan = _scan(client, "secrets.cfg", SECRETS)
    body = {"scan_id": scan["scan_id"], "rule_id": "MGMT-001",
            "device_hostname": scan["devices"][0]["hostname"], "config_index": 0}
    client.post("/api/remediation/candidate", json={**body, "command": "delete system services telnet;"})
    verified = client.post("/api/remediation/candidate/verify", json=body).json()
    assert verified["status"] == "verified"
    # the JSON the browser gets still carries no secret
    assert not any(s in verified["reason"] + verified["diff"] for s in ("$9$SuperSecretHash", "TopSecret123"))
    # the file is the administrator's own upload, minus the failing line: it adds no secret and loses none
    assert _download(client, body).text == cand.apply_to_copy(SECRETS, [_line_of(SECRETS, "telnet;")])

    routes = pathlib.Path(__file__).parent.parent / "app" / "api" / "routes" / "remediation.py"
    source = pathlib.Path(cand.__file__).read_text() + routes.read_text()
    assert not re.search(r"socket|paramiko|telnetlib|netmiko|requests\.|httpx|ssh_client|subprocess", source, re.I)
