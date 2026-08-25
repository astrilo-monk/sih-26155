"""
AI client wrapper.

Handles communication with the Gemini API. Designed to fail
gracefully when no API key is configured — the app works
without AI, it just won't have explanations and chat.
"""

from __future__ import annotations
from typing import Optional
from app.config import settings


_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client

    if not settings.gemini_api_key:
        return None

    try:
        from google import genai
        _client = genai.Client(api_key=settings.gemini_api_key)
        return _client
    except Exception as e:
        print(f"Warning: Could not initialize Gemini client: {e}")
        return None


def generate(prompt: str, system_instruction: str = "") -> Optional[str]:
    """
    Send a prompt to Gemini and get a response.
    Returns None if AI is unavailable.
    """
    client = _get_client()
    if not client:
        return None

    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config={
                "system_instruction": system_instruction,
                "temperature": 0.3,
                "max_output_tokens": 1024,
            },
        )
        return response.text
    except Exception as e:
        print(f"Warning: Gemini API call failed: {e}")
        return None


def is_available() -> bool:
    """Check if AI features are available."""
    return _get_client() is not None
