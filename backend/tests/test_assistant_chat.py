"""
The assistant's context and conversation.

The assistant is the one place where a free-text question meets the scan, so what matters is what it
is allowed to know: the redacted results, never the configuration. No test reaches a provider -
``generate`` is patched, because a developer .env may hold a real key.
"""

from __future__ import annotations

import io
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.api.routes.assistant import MAX_HISTORY_TURNS, _scan_context
from app.main import app

# Weak on purpose, and every secret in it is a distinct string so a leak is unambiguous
CISCO = """hostname EDGE-01
enable password cisco123
no service password-encryption
username admin privilege 15 password 0 adminpw456
snmp-server community publiccomm RO
ip http server
line vty 0 4
 transport input telnet ssh
!
end
"""


@pytest.fixture
def client(seeded_adaptive_db):
    return TestClient(app)


def _scan(client) -> str:
    r = client.post("/api/scan", files={"files": ("edge.cfg", io.BytesIO(CISCO.encode()), "text/plain")})
    assert r.status_code == 200, r.text
    return r.json()["scan_id"]


def _ask(client, scan_id, message, history=None):
    """Ask, capturing the prompt the provider would have been given."""
    seen = {}

    def fake_generate(prompt, system):
        seen["prompt"], seen["system"] = prompt, system
        return "answer"

    with patch("app.api.routes.assistant.is_available", return_value=True), \
         patch("app.api.routes.assistant.generate", fake_generate):
        r = client.post("/api/assistant/chat", json={
            "scan_id": scan_id, "message": message, "history": history or []})
    assert r.status_code == 200, r.text
    return r.json(), seen


# -- what the assistant is allowed to know -----------------------------------------------------

def test_the_context_is_the_redacted_view_so_no_secret_can_reach_the_provider(client):
    """Built from the response the browser already has, which has had its secrets removed. A path
    that forgot to scrub one cannot leak it here, because this never reads the raw configuration."""
    context = _scan_context(_scan(client))
    for secret in ("cisco123", "adminpw456", "publiccomm"):
        assert secret not in context


def test_the_context_carries_the_checks_that_were_not_decided(client):
    """The engine's distinctive output is what it refuses to claim. An assistant that only saw
    findings would report a clean device as compliant when most checks were never decided."""
    context = _scan_context(_scan(client))
    assert "EVERY CHECK, INCLUDING THE ONES NOT DECIDED" in context
    assert "not_configured" in context or "unknown" in context
    # and the numbers that separate "scored well" from "barely assessed"
    assert "Posture:" in context and "Coverage:" in context


def test_the_system_prompt_tells_the_model_not_to_call_an_undecided_check_a_failure(client):
    _, seen = _ask(client, _scan(client), "how did this device do?")
    assert "NOT failures" in seen["system"]
    assert "never invent" in seen["system"].lower()


# -- the conversation --------------------------------------------------------------------------

def test_a_follow_up_can_refer_to_what_was_already_said(client):
    _, seen = _ask(client, _scan(client), "why?", history=[
        {"role": "you", "content": "what should I fix first?"},
        {"role": "assistant", "content": "Telnet, MGMT-001."},
    ])
    assert "what should I fix first?" in seen["prompt"]
    assert "Telnet, MGMT-001." in seen["prompt"]
    assert "Operator's question: why?" in seen["prompt"]


def test_a_long_conversation_is_trimmed_rather_than_sent_whole(client):
    history = [{"role": "you", "content": f"question {i}"} for i in range(40)]
    _, seen = _ask(client, _scan(client), "and now?", history=history)
    assert "question 39" in seen["prompt"]          # the recent turns survive
    assert "question 0" not in seen["prompt"]       # the oldest do not
    assert seen["prompt"].count("question ") <= MAX_HISTORY_TURNS


def test_a_secret_typed_into_the_chat_is_scrubbed_before_it_is_sent(client):
    """The operator may paste a line from the device. It must not travel further than this process."""
    _, seen = _ask(client, _scan(client), "is enable password cisco123 weak?")
    assert "cisco123" not in seen["prompt"]


def test_a_secret_in_the_conversation_history_is_scrubbed_too(client):
    _, seen = _ask(client, _scan(client), "and now?", history=[
        {"role": "you", "content": "what about snmp-server community publiccomm RO"}])
    assert "publiccomm" not in seen["prompt"]


# -- when it cannot answer ---------------------------------------------------------------------

def test_a_scan_this_backend_no_longer_holds_is_explained_not_answered_blindly(client):
    """Without the scan there is no context, and answering anyway would be invention."""
    with patch("app.api.routes.assistant.is_available", return_value=True), \
         patch("app.api.routes.assistant.generate", lambda *a: "should never be called"):
        r = client.post("/api/assistant/chat", json={"scan_id": "no-such-scan", "message": "hi"})
    assert r.status_code == 200
    assert "no longer holds that scan" in r.json()["response"]


def test_without_ai_configured_the_assistant_says_so(client):
    with patch("app.api.routes.assistant.is_available", return_value=False):
        r = client.post("/api/assistant/chat", json={"scan_id": _scan(client), "message": "hi"})
    assert r.status_code == 200
    assert "not configured" in r.json()["response"].lower()
