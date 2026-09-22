"""
Groq API-key rotation in ``request_structured``.

Keys are tried in configured order (GROQ_API_KEY_1 → _4). A request moves to
the next key only for failures another key could fix: rate limits / quota
(429) and key-specific rejections (401, 403, 404). Request-level failures
(400, timeout, network) return immediately and are handled by the
interpreter's retry/split logic.

Every Groq call is faked with the SDK's real exception classes; no network
access happens.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import groq
import httpx
import pytest

from app.adaptive import interpreter
from app.ai import client as ai_client
from app.models.normalized import UnrecognizedLine

_REQUEST = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
KEYS = ["gsk_test_key_one", "gsk_test_key_two", "gsk_test_key_three", "gsk_test_key_four"]
OK = "ok"


def _status_error(cls, code: int, message: str) -> Exception:
    return cls(message, response=httpx.Response(code, request=_REQUEST), body=None)


def ok():
    return OK


def unauthorized():
    return _status_error(groq.AuthenticationError, 401,
                         "Error code: 401 - {'error': {'message': 'Invalid API Key', 'code': 'invalid_api_key'}}")


def forbidden():
    return _status_error(groq.PermissionDeniedError, 403,
                         "Error code: 403 - {'error': {'message': 'Forbidden', 'code': 'permission_denied'}}")


def model_not_found():
    return _status_error(groq.NotFoundError, 404,
                         "Error code: 404 - {'error': {'message': 'The model `openai/gpt-oss-120b` does not exist "
                         "or you do not have access to it.', 'code': 'model_not_found'}}")


def bad_request():
    return _status_error(groq.BadRequestError, 400,
                         "Error code: 400 - {'error': {'message': 'Invalid request', 'type': 'invalid_request_error'}}")


def daily_quota():
    return _status_error(groq.RateLimitError, 429,
                         "Error code: 429 - {'error': {'message': 'Rate limit reached for model `openai/gpt-oss-120b` "
                         "in organization `org_test` on tokens per day (TPD): Limit 200000', 'code': 'rate_limit_exceeded'}}")


def timeout():
    return groq.APITimeoutError(request=_REQUEST)


def network():
    return groq.APIConnectionError(request=_REQUEST)


@pytest.fixture
def keys(monkeypatch):
    """Install four fake keys. ``keys(*outcomes)`` scripts each key in order
    (unscripted keys succeed) and returns the list of key indexes called."""
    calls: list[int] = []
    behaviours: dict[int, object] = {}

    def get_client(index):
        def create(**kwargs):
            calls.append(index)
            outcome = behaviours[index]()
            if outcome == OK:
                return SimpleNamespace(choices=[SimpleNamespace(
                    message=SimpleNamespace(content='{"interpretations": []}'),
                )])
            raise outcome
        return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))

    monkeypatch.setattr(ai_client, "_api_keys", list(KEYS))
    monkeypatch.setattr(ai_client, "_get_client", get_client)

    def script(*outcomes):
        calls.clear()
        behaviours.clear()
        for index in range(len(KEYS)):
            behaviours[index] = outcomes[index] if index < len(outcomes) else ok
        return calls

    return script


def _request():
    return ai_client.request_structured("Return JSON.", {"type": "json_object"})


# A, B, C ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("failure", [unauthorized, forbidden, model_not_found], ids=["401", "403", "404"])
def test_key_specific_failure_falls_through_to_next_key(keys, failure):
    calls = keys(failure, ok)
    response = _request()
    assert calls == [0, 1]
    assert response.ok
    assert response.data == {"interpretations": []}


# D ───────────────────────────────────────────────────────────────────────────

def test_consecutive_key_specific_failures_reach_third_key(keys):
    calls = keys(unauthorized, forbidden, ok)
    response = _request()
    assert calls == [0, 1, 2]
    assert response.ok


# E ───────────────────────────────────────────────────────────────────────────

def test_all_keys_rejected_tries_each_key_once_and_fails(keys, caplog):
    calls = keys(unauthorized, unauthorized, unauthorized, unauthorized)
    with caplog.at_level(logging.DEBUG, logger="app.ai.client"):
        response = _request()

    assert calls == [0, 1, 2, 3]
    assert response.error == ai_client.ERROR_REQUEST_FAILED
    assert not response.ok and not response.quota_exhausted
    assert "401" in response.detail
    # key material never reaches logs or the returned detail
    assert not any(key in caplog.text or key in response.detail for key in KEYS)


# F ───────────────────────────────────────────────────────────────────────────

def test_daily_quota_on_every_key_still_reports_quota_exhausted(keys):
    calls = keys(daily_quota, daily_quota, daily_quota, daily_quota)
    response = _request()
    assert calls == [0, 1, 2, 3]
    assert response.quota_exhausted
    assert not response.retryable


def test_rejected_key_plus_exhausted_quota_on_the_rest_is_quota_exhaustion(keys):
    calls = keys(unauthorized, daily_quota, daily_quota, daily_quota)
    response = _request()
    assert calls == [0, 1, 2, 3]
    assert response.quota_exhausted


# G ───────────────────────────────────────────────────────────────────────────

def test_bad_request_does_not_try_other_keys(keys):
    calls = keys(bad_request, ok)
    response = _request()
    assert calls == [0]
    assert response.error == ai_client.ERROR_REQUEST_FAILED


# H ───────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("failure", [timeout, network], ids=["timeout", "network"])
def test_timeout_and_network_failures_do_not_fan_out(keys, failure):
    calls = keys(failure, ok)
    response = _request()
    assert calls == [0]
    assert response.error == ai_client.ERROR_REQUEST_FAILED
    assert response.retryable


@pytest.mark.parametrize("failure", [timeout, network], ids=["timeout", "network"])
def test_interpreter_retry_and_split_still_handle_request_failures(keys, monkeypatch, failure):
    monkeypatch.setattr(interpreter, "is_available", lambda: True)
    calls = keys(failure, ok, ok, ok)
    lines = [
        UnrecognizedLine(raw_line="set ssh enable", line_number=1, vendor="unknown"),
        UnrecognizedLine(raw_line="set telnet disable", line_number=2, vendor="unknown"),
    ]

    results = interpreter.interpret_lines(lines)

    assert calls == [0, 0, 0, 0]              # retry once, then one request per half -key 0 only
    assert all(r.status.value == "ai_unavailable" for r in results)
