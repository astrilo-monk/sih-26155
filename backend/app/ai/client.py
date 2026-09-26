"""
AI client wrapper.

Handles communication with the Groq API, or with a local OpenAI-compatible server (Ollama, llama.cpp) when
``LOCAL_AI_URL`` is set, for networks that cannot reach the internet. Designed to fail
gracefully when no API key is configured -the app works
without AI, it just won't have explanations and chat.

Provider is isolated behind this layer. All AI calls go through
the functions defined here.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)


_api_keys: list[str] = []
_clients: list = []


class _LocalClient:
    """The one call this module makes (``client.chat.completions.create``) against a local OpenAI-compatible
    server. The Groq SDK cannot be pointed there: it hard-codes its ``/openai/v1`` path."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.chat = self.completions = self

    def create(self, *, timeout: float = 30.0, **params):
        import httpx
        from types import SimpleNamespace

        params["model"] = settings.local_ai_model  # callers name Groq's model
        params.pop("reasoning_effort", None)  # Groq-only
        body = {k: v for k, v in params.items() if v is not None}
        r = httpx.post(f"{self.base_url}/chat/completions", json=body,
                       timeout=max(timeout, settings.local_ai_timeout))
        if r.status_code >= 400:  # "Error code: N" is what _status_code() reads
            raise RuntimeError(f"Error code: {r.status_code} - {r.text[:200]}")
        content = r.json()["choices"][0]["message"]["content"]
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])


def provider() -> Optional[str]:
    """``"local"``, ``"groq"``, or None when no AI is configured."""
    if settings.local_ai_url.strip():
        return "local"
    return "groq" if is_available() else None


def _init_keys():
    """Build the list of Groq API keys from settings, deduplicated. A local server is the only "key" when set."""
    global _api_keys, _clients
    if settings.local_ai_url.strip():
        _api_keys, _clients = ["local"], [_LocalClient(settings.local_ai_url.strip())]
        return
    keys = []
    for k in (
        settings.groq_api_key,
        settings.groq_api_key_1,
        settings.groq_api_key_2,
        settings.groq_api_key_3,
        settings.groq_api_key_4,
    ):
        k = (k or "").strip()
        if k and k not in keys:
            keys.append(k)
    _api_keys = keys
    _clients = []


def _get_client(index: int = 0):
    """Return a configured Groq client at the given key index, or None."""
    if not _api_keys:
        _init_keys()
    if not _api_keys:
        return None

    if index >= len(_clients):
        # Lazily create clients up to index
        while len(_clients) <= index:
            try:
                from groq import Groq
                _clients.append(Groq(api_key=_api_keys[len(_clients)]))
            except Exception as e:
                logger.warning("Could not initialize Groq client %d: %s", len(_clients), e)
                _clients.append(None)

    return _clients[index]


def _is_rate_limited(exc: Exception) -> bool:
    """Check if an exception is a Groq rate-limit (429) error."""
    msg = str(exc)
    return "429" in msg or "rate_limit" in msg or "rate limit" in msg.lower()


def is_available() -> bool:
    """Check if AI features are available."""
    return _get_client(0) is not None


def generate(
    prompt: str,
    system_instruction: str = "",
    model: str = "openai/gpt-oss-120b",
    temperature: float = 0.3,
    max_tokens: int = 1024,
    timeout: float = 30.0,
) -> Optional[str]:
    """
    Send a prompt to Groq and get a text response.

    Returns None if AI is unavailable or the call fails.
    """
    if not _api_keys:
        _init_keys()
    if not _api_keys:
        return None

    messages = []
    if system_instruction:
        messages.append({"role": "system", "content": system_instruction})
    messages.append({"role": "user", "content": prompt})

    last_exc: Exception | None = None
    for key_index in range(len(_api_keys)):
        client = _get_client(key_index)
        if not client:
            continue
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
            )
            return response.choices[0].message.content
        except Exception as e:
            last_exc = e
            if _is_rate_limited(e):
                logger.warning("Groq rate-limited on key %d, trying next key", key_index)
                continue
            logger.warning("Groq API call failed: %s", e)
            return None

    if last_exc:
        logger.warning("All Groq API keys exhausted: %s", last_exc)
    return None


# Structured-request failure kinds
ERROR_UNAVAILABLE = "unavailable"          # no API key / client
ERROR_QUOTA_EXHAUSTED = "quota_exhausted"  # daily token/request budget used up
ERROR_RATE_LIMITED = "rate_limited"        # short-window limit on every key
ERROR_INVALID_OUTPUT = "invalid_output"    # empty or non-JSON content
ERROR_REQUEST_FAILED = "request_failed"    # timeout, network, 5xx, bad request

_RETRYABLE_ERRORS = frozenset({ERROR_RATE_LIMITED, ERROR_INVALID_OUTPUT, ERROR_REQUEST_FAILED})


@dataclass
class StructuredResponse:
    """Outcome of a structured request: parsed data, or a classified error."""
    data: Optional[dict] = None
    error: Optional[str] = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.data is not None

    @property
    def retryable(self) -> bool:
        return self.error in _RETRYABLE_ERRORS

    @property
    def quota_exhausted(self) -> bool:
        return self.error == ERROR_QUOTA_EXHAUSTED


def _is_quota_exhausted(exc: Exception) -> bool:
    """A daily budget (tokens/requests per day) cannot be fixed by retrying soon."""
    msg = str(exc).lower()
    return "per day" in msg or "(tpd)" in msg or "(rpd)" in msg


# Failures that may be specific to one API key (revoked/invalid key, a key
# without access to the model) -another configured key can still succeed.
_KEY_SPECIFIC_STATUSES = frozenset({401, 403, 404})


def _status_code(exc: Exception) -> Optional[int]:
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    match = re.search(r"Error code: (\d{3})", str(exc))
    return int(match.group(1)) if match else None


def _is_key_specific(exc: Exception) -> bool:
    return _status_code(exc) in _KEY_SPECIFIC_STATUSES


def request_structured(
    prompt: str,
    response_format: dict,
    system_instruction: str = "",
    model: str = "openai/gpt-oss-120b",
    temperature: float = 0.0,
    max_tokens: int = 4096,
    timeout: float = 30.0,
    seed: int | None = None,
    top_p: float | None = None,
    reasoning_effort: str | None = None,
) -> StructuredResponse:
    """
    Send a structured (JSON Schema) request to Groq and classify the outcome.

    Tries the configured API keys in order. A key is skipped in favour of the
    next one when it is rate-limited (429) or rejected in a way that may be
    specific to that key (401, 403, 404). Keys that belong to the same Groq
    organization share one budget, so a daily-quota error on every key is
    reported as ``quota_exhausted`` rather than retried. Request-level
    failures (400, timeout, network) return immediately without trying the
    remaining keys.
    """
    if not _api_keys:
        _init_keys()
    if not _api_keys:
        return StructuredResponse(error=ERROR_UNAVAILABLE, detail="No Groq API key configured")

    messages = []
    if system_instruction:
        messages.append({"role": "system", "content": system_instruction})
    messages.append({"role": "user", "content": prompt})

    params = dict(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        response_format=response_format,
        timeout=timeout,
        seed=seed,
    )
    if top_p is not None:
        params["top_p"] = top_p
    if reasoning_effort is not None:
        params["reasoning_effort"] = reasoning_effort

    limited: list[Exception] = []
    rejected: list[Exception] = []
    for key_index in range(len(_api_keys)):
        client = _get_client(key_index)
        if not client:
            continue
        try:
            response = client.chat.completions.create(**params)
        except Exception as e:
            if _is_rate_limited(e):
                logger.warning("Groq rate-limited on key %d, trying next key", key_index)
                limited.append(e)
                continue
            if _is_key_specific(e):
                logger.warning(
                    "Groq rejected key %d (HTTP %s), trying next key", key_index, _status_code(e),
                )
                rejected.append(e)
                continue
            logger.warning("Groq structured API call failed: %s", e)
            return StructuredResponse(error=ERROR_REQUEST_FAILED, detail=str(e)[:300])

        content = response.choices[0].message.content
        if not content:
            return StructuredResponse(error=ERROR_INVALID_OUTPUT, detail="Empty response content")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.warning("Groq structured output was not valid JSON: %s", e)
            return StructuredResponse(error=ERROR_INVALID_OUTPUT, detail=str(e))
        if not isinstance(data, dict):
            return StructuredResponse(error=ERROR_INVALID_OUTPUT, detail="Response is not a JSON object")
        return StructuredResponse(data=data)

    if limited:
        logger.warning("All Groq API keys rate-limited: %s", limited[-1])
        kind = ERROR_QUOTA_EXHAUSTED if all(_is_quota_exhausted(e) for e in limited) else ERROR_RATE_LIMITED
        return StructuredResponse(error=kind, detail=str(limited[-1])[:300])
    if rejected:
        logger.warning("Every Groq API key was rejected: %s", rejected[-1])
        return StructuredResponse(error=ERROR_REQUEST_FAILED, detail=str(rejected[-1])[:300])
    return StructuredResponse(error=ERROR_UNAVAILABLE, detail="No Groq client could be initialized")


def generate_structured(
    prompt: str,
    response_format: dict,
    system_instruction: str = "",
    model: str = "openai/gpt-oss-120b",
    temperature: float = 0.1,
    max_tokens: int = 4096,
    timeout: float = 30.0,
    seed: int | None = None,
) -> Optional[dict]:
    """
    Send a prompt to Groq and get a structured JSON response.

    Returns parsed JSON dict, or None if unavailable/fails. Use
    :func:`request_structured` when the failure kind matters.
    """
    return request_structured(
        prompt=prompt,
        response_format=response_format,
        system_instruction=system_instruction,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        seed=seed,
    ).data
