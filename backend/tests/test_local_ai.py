"""Offline AI: LOCAL_AI_URL sends every AI call to a local OpenAI-compatible server instead of Groq."""

import json

import httpx
import pytest

from app.ai import client
from app.config import settings


class _Reply:
    def __init__(self, status, payload):
        self.status_code, self._payload, self.text = status, payload, json.dumps(payload)

    def json(self):
        return self._payload


@pytest.fixture
def local(monkeypatch):
    monkeypatch.setattr(settings, "local_ai_url", "http://127.0.0.1:11434/v1/")
    monkeypatch.setattr(settings, "local_ai_model", "llama3.1:8b")
    monkeypatch.setattr(client, "_api_keys", [])
    monkeypatch.setattr(client, "_clients", [])

    class Sent(list):
        reply = None

    sent = Sent()

    def post(url, json, timeout):
        sent.append({"url": url, "body": json, "timeout": timeout})
        return sent.reply

    sent.reply = _Reply(200, {"choices": [{"message": {"content": '{"verdict": "fail"}'}}]})
    monkeypatch.setattr(httpx, "post", post)
    return sent


def test_calls_go_to_the_local_server_with_its_model(local):
    out = client.request_structured("q", {"type": "json_object"}, model="openai/gpt-oss-120b",
                                    reasoning_effort="low", timeout=30)
    assert out.data == {"verdict": "fail"}
    [call] = local
    assert call["url"] == "http://127.0.0.1:11434/v1/chat/completions"
    assert call["body"]["model"] == "llama3.1:8b" and "reasoning_effort" not in call["body"]
    assert call["timeout"] == settings.local_ai_timeout  # slow local models get longer than Groq's 30 s
    assert client.is_available() and client.provider() == "local"


def test_a_server_error_is_a_classified_failure_not_a_crash(local):
    local.reply = _Reply(500, {"error": "model not loaded"})
    out = client.request_structured("q", {"type": "json_object"})
    assert out.error == client.ERROR_REQUEST_FAILED and "500" in out.detail
