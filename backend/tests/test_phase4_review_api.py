"""
Phase 4 -Admin training API tests.

Covers: queue listing, accept, edit, reject, invalid field, invalid value,
already-reviewed items, rejected lines not retried, admin mapping management.
All AI calls are mocked.

Phase 7: AI review items come only from the legacy line interpreter, which is reachable only for confirmed
vendors behind ``adaptive_ai_for_known_vendors`` (off by default). These tests turn it on for a Cisco config
whose appended lines the parser does not read; every interpretation lands in the queue, none is applied.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import app.config as app_config
from app.ai.interpretation_schemas import ConfidenceLevel, InterpretationResult, InterpretationStatus
from app.api.routes.scan import get_scan_store
from app.main import app


# A confirmed Cisco IOS config: no logging, NTP or SSH version, and no line the capture step keeps
BASE = """\
hostname EDGE-RTR
!
service password-encryption
enable secret 9 $9$abcdefghijklmn
username admin privilege 15 secret 9 $9$abcdefghijklmn
aaa new-model
ip domain-name corp.example
no ip http server
no ip source-route
no cdp run
!
line con 0
 exec-timeout 5 0
line vty 0 4
 transport input ssh
 exec-timeout 5 0
!
"""
FIRST = len(BASE.splitlines()) + 1

CONFIG = (
    "secure-shell protocol-version 1\n"
    "remote-console protocol telnet\n"
    "audit-stream destination 10.44.60.20\n"
)

SUGGESTIONS = {
    "secure-shell": ("management.ssh_version", "1", 0.75, "ssh_protocol_version"),
    "remote-console": ("management.telnet_enabled", "true", 0.70, "telnet_management"),
    "audit-stream": ("logging.remote_hosts", "10.44.60.20", 0.30, "remote_syslog"),
}


def _interpret(lines):
    results = []
    for ln in lines:
        key = ln.raw_line.split()[0]
        field, value, confidence, concept = SUGGESTIONS.get(key, ("unknown", None, 0.2, "unknown"))
        results.append(InterpretationResult(
            line_number=ln.line_number,
            raw_line=ln.raw_line,
            likely_vendor="generic",
            security_concept=concept,
            normalized_field=field,
            extracted_value=value,
            confidence=ConfidenceLevel.MEDIUM if confidence >= 0.5 else ConfidenceLevel.LOW,
            numeric_confidence=confidence,
            reasoning=f"Interpreted {key}",
            status=InterpretationStatus.INTERPRETED if value else InterpretationStatus.UNKNOWN,
        ))
    return results


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(app_config.settings, "adaptive_ai_for_known_vendors", True)
    return TestClient(app)


def _scan(client, text=CONFIG, interpreter=None):
    interpreter = interpreter or MagicMock(side_effect=_interpret)
    with patch("app.api.routes.scan.interpret_lines", interpreter), \
         patch("app.api.routes.scan.is_available", return_value=True):
        resp = client.post("/api/scan", files=[("files", ("device.cfg", (BASE + text).encode(), "text/plain"))])
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    assert scan["devices"][0]["vendor"] == "cisco_ios"
    return scan


def _queue(client, scan_id, **params):
    resp = client.get(f"/api/adaptive/scans/{scan_id}/review", params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _item_for(queue, prefix):
    return next(i for i in queue["items"] if i["raw_line"].startswith(prefix))


def _rule_ids(scan):
    return {f["rule_id"] for f in scan["findings"]}


def test_review_queue_lists_unresolved_interpretations(client):
    scan = _scan(client)
    queue = _queue(client, scan["scan_id"])

    assert queue["pending_count"] == 3
    item = _item_for(queue, "secure-shell")
    assert item["line_number"] == FIRST
    assert item["context_after"] == ["remote-console protocol telnet", "audit-stream destination 10.44.60.20"]
    assert item["normalized_field"] == "management.ssh_version"
    assert item["extracted_value"] == "1"
    assert item["confidence"] == 0.75
    assert item["confidence_tier"] == "medium"
    assert item["reasoning"] == "Interpreted secure-shell"
    assert item["review_status"] == "pending"

    assert _item_for(queue, "audit-stream")["source"] == "needs_training"

    # Score is flagged provisional while lines are pending
    assert scan["adaptive"]["score_provisional"] is True
    assert scan["adaptive"]["pending_review"] == 3


def test_accept_persists_mapping_and_rescans(client):
    scan = _scan(client)
    scan_id = scan["scan_id"]
    # Nothing applied yet: the parser reads no remote log host, so LOG-001 fails
    assert "LOG-001" in _rule_ids(scan)

    item = _item_for(_queue(client, scan_id), "audit-stream")
    resp = client.post(f"/api/adaptive/scans/{scan_id}/review/{item['item_id']}/accept")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["item"]["review_status"] == "accepted"
    assert body["item"]["source"] == "admin_confirmed"
    assert body["mapping"]["command_pattern"] == "audit-stream destination {value}"
    assert body["mapping"]["confirmed"] is True
    # Deterministic rule re-evaluated on the confirmed value
    assert "LOG-001" not in _rule_ids(body["scan"])
    assert body["scan"]["score"] > scan["score"] and body["scan"]["adaptive"]["assessed"] is True

    config = get_scan_store()[scan_id]["configs"][0]
    assert config.logging.remote_hosts == ["10.44.60.20"]

    mappings = client.get("/api/adaptive/mappings").json()
    assert [m["id"] for m in mappings] == [body["mapping"]["id"]]
    assert _queue(client, scan_id)["pending_count"] == 2


def test_edit_persists_corrected_mapping(client):
    scan = _scan(client)
    scan_id = scan["scan_id"]
    item = _item_for(_queue(client, scan_id), "remote-console")

    resp = client.post(
        f"/api/adaptive/scans/{scan_id}/review/{item['item_id']}/edit",
        json={"normalized_field": "management.telnet_enabled", "extracted_value": "enabled", "concept": "telnet_exposure"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["item"]["review_status"] == "edited"
    assert body["mapping"]["extraction_method"] == "constant"
    assert body["mapping"]["constant_value"] == "enabled"
    assert body["mapping"]["concept"] == "telnet_exposure"
    assert get_scan_store()[scan_id]["configs"][0].management.telnet_enabled is True


def test_edit_with_explicit_command_pattern(client):
    scan = _scan(client)
    item = _item_for(_queue(client, scan["scan_id"]), "secure-shell")

    resp = client.post(
        f"/api/adaptive/scans/{scan['scan_id']}/review/{item['item_id']}/edit",
        json={"normalized_field": "management.ssh_version", "extracted_value": "1",
              "command_pattern": "secure-shell {any} {value}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["mapping"]["command_pattern"] == "secure-shell {any} {value}"


@pytest.mark.parametrize("payload,status", [
    ({"normalized_field": "made.up_field", "extracted_value": "1"}, 422),
    ({"normalized_field": "interfaces[].name", "extracted_value": "Gi0/0"}, 422),
    ({"normalized_field": "management.ssh_version", "extracted_value": "modern"}, 422),
    ({"normalized_field": "management.telnet_enabled", "extracted_value": "perhaps"}, 422),
    ({"normalized_field": "management.ssh_version", "extracted_value": ""}, 422),
    ({"normalized_field": "management.ssh_version"}, 422),
    ({"normalized_field": "management.ssh_version", "extracted_value": "1", "command_pattern": "ssh .*"}, 422),
    ({"normalized_field": "management.ssh_version", "extracted_value": "1", "command_pattern": "secure-shell {value} {value}"}, 422),
])
def test_invalid_edits_rejected(client, payload, status):
    scan = _scan(client)
    item = _item_for(_queue(client, scan["scan_id"]), "secure-shell")

    resp = client.post(f"/api/adaptive/scans/{scan['scan_id']}/review/{item['item_id']}/edit", json=payload)
    assert resp.status_code == status, resp.text
    assert client.get("/api/adaptive/mappings").json() == []
    assert _queue(client, scan["scan_id"])["pending_count"] == 3


def test_accept_without_usable_suggestion_requires_edit(client):
    scan = _scan(client, "control-plane rate-guard 1200\n")
    item = _queue(client, scan["scan_id"])["items"][0]

    resp = client.post(f"/api/adaptive/scans/{scan['scan_id']}/review/{item['item_id']}/accept")
    assert resp.status_code == 422


def test_reject_marks_reviewed_and_is_not_retried(client):
    scan = _scan(client)
    scan_id = scan["scan_id"]
    item = _item_for(_queue(client, scan_id), "secure-shell")

    resp = client.post(f"/api/adaptive/scans/{scan_id}/review/{item['item_id']}/reject", json={"reason": "cosmetic"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["item"]["review_status"] == "rejected"
    assert resp.json()["mapping"] is None
    assert get_scan_store()[scan_id]["configs"][0].management.ssh_version is None

    # Next scan: the rejected line is not sent to the AI again
    interpreter = MagicMock(side_effect=_interpret)
    second = _scan(client, interpreter=interpreter)
    sent = [ln.raw_line for ln in interpreter.call_args.args[0]]
    assert "secure-shell protocol-version 1" not in sent
    assert len(sent) == 2
    assert _item_for({"items": second["adaptive"]["ai_mappings"]}, "secure-shell")["source"] == "rejected"


def test_already_reviewed_item_conflicts(client):
    scan = _scan(client)
    scan_id = scan["scan_id"]
    item = _item_for(_queue(client, scan_id), "audit-stream")
    url = f"/api/adaptive/scans/{scan_id}/review/{item['item_id']}"

    assert client.post(f"{url}/accept").status_code == 200
    assert client.post(f"{url}/accept").status_code == 409
    assert client.post(f"{url}/reject").status_code == 409
    assert client.post(f"{url}/edit", json={"normalized_field": "logging.remote_hosts", "extracted_value": "1.1.1.1"}).status_code == 409

    resolved = _queue(client, scan_id, include_resolved=True)
    assert _item_for(resolved, "audit-stream")["review_status"] == "accepted"


def test_unknown_scan_or_item_returns_404(client):
    assert client.get("/api/adaptive/scans/nope/review").status_code == 404
    scan = _scan(client)
    assert client.post(f"/api/adaptive/scans/{scan['scan_id']}/review/0-999/accept").status_code == 404
    assert client.post(f"/api/adaptive/scans/{scan['scan_id']}/review/garbage/reject").status_code == 404


def test_confirmed_mapping_resolves_same_syntax_elsewhere_in_scan(client):
    text = "audit-stream destination 10.1.1.1\naudit-stream destination 10.2.2.2\n"
    scan = _scan(client, text)
    scan_id = scan["scan_id"]
    queue = _queue(client, scan_id)
    first, second = queue["items"]

    body = client.post(f"/api/adaptive/scans/{scan_id}/review/{first['item_id']}/edit",
                       json={"normalized_field": "logging.remote_hosts", "extracted_value": "10.1.1.1"}).json()

    assert body["auto_resolved"] == [second["item_id"]]
    assert get_scan_store()[scan_id]["configs"][0].logging.remote_hosts == ["10.1.1.1", "10.2.2.2"]
    assert _queue(client, scan_id)["pending_count"] == 0


def test_admin_can_update_and_disable_mappings(client):
    scan = _scan(client)
    item = _item_for(_queue(client, scan["scan_id"]), "audit-stream")
    mapping = client.post(f"/api/adaptive/scans/{scan['scan_id']}/review/{item['item_id']}/accept").json()["mapping"]

    patched = client.patch(f"/api/adaptive/mappings/{mapping['id']}", json={"concept": "syslog_destination"})
    assert patched.status_code == 200
    assert patched.json()["concept"] == "syslog_destination"

    bad = client.patch(f"/api/adaptive/mappings/{mapping['id']}", json={"normalized_field": "interfaces[].name"})
    assert bad.status_code == 422

    disabled = client.delete(f"/api/adaptive/mappings/{mapping['id']}")
    assert disabled.status_code == 200 and disabled.json()["active"] is False
    assert client.get("/api/adaptive/mappings").json() == []
    assert len(client.get("/api/adaptive/mappings", params={"include_inactive": True}).json()) == 1
    assert client.delete("/api/adaptive/mappings/9999").status_code == 404


def test_fields_endpoint_lists_settable_fields(client):
    fields = {f["field"]: f["value_type"] for f in client.get("/api/adaptive/fields").json()}
    assert fields["management.ssh_version"] == "optional_int"
    assert fields["logging.remote_hosts"] == "list_str"
    assert not any("[]" in name for name in fields)


def test_display_only_scan_returns_409_for_result_routes(client):
    # display-only remains only when lexicon heuristics find nothing either (Phase 5); unknown vendor, AI off
    with patch("app.api.routes.scan.is_available", return_value=False), \
         patch("app.api.routes.scan.facts_from_config", return_value=[]):
        scan = client.post("/api/scan", files=[("files", ("d.cfg", CONFIG.encode(), "text/plain"))]).json()
    assert scan["score"] is None and scan["devices"][0]["vendor"] == "unknown"

    assert client.post("/api/download-fixed", json={"scan_id": scan["scan_id"]}).status_code == 409
    assert client.get(f"/api/assistant/summary/{scan['scan_id']}").status_code == 409
    # Unknown vendors never reach the legacy interpreter (Phase 7): nothing is queued for line review
    assert _queue(client, scan["scan_id"])["pending_count"] == 0
