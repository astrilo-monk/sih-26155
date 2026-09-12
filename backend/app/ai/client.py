"""
AI client wrapper.

Handles communication with the Groq API. Designed to fail
gracefully when no API key is configured — the app works
without AI, it just won't have explanations and chat.

Provider is isolated behind this layer. All AI calls go through
the functions defined here.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)


_client = None


def _get_client():
    """Return a configured Groq client, or None if unavailable."""
    global _client
    if _client is not None:
        return _client

    if not settings.groq_api_key:
        return None

    try:
        from groq import Groq
        _client = Groq(api_key=settings.groq_api_key)
        return _client
    except Exception as e:
        logger.warning("Could not initialize Groq client: %s", e)
        return None


def is_available() -> bool:
    """Check if AI features are available."""
    return _get_client() is not None


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
    client = _get_client()
    if not client:
        return None

    try:
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.warning("Groq API call failed: %s", e)
        return None


def generate_structured(
    prompt: str,
    response_format: dict,
    system_instruction: str = "",
    model: str = "openai/gpt-oss-120b",
    temperature: float = 0.1,
    max_tokens: int = 4096,
    timeout: float = 30.0,
) -> Optional[dict]:
    """
    Send a prompt to Groq and get a structured JSON response.

    Uses Groq's JSON Schema structured output support.
    Returns parsed JSON dict, or None if unavailable/fails.
    """
    client = _get_client()
    if not client:
        return None

    try:
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
            timeout=timeout,
        )

        content = response.choices[0].message.content
        if not content:
            return None

        return json.loads(content)
    except json.JSONDecodeError as e:
        logger.warning("Groq structured output was not valid JSON: %s", e)
        return None
    except Exception as e:
        logger.warning("Groq structured API call failed: %s", e)
        return None