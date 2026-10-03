"""
Who is calling, and so whose taught knowledge a request reads and writes (``app.db.mappings``).

Accounts are on when ``SUPABASE_URL`` is set:

* ``Authorization: Bearer <Supabase access token>`` -> the account's own mappings, in the main store
  (Postgres when ``DATABASE_URL`` is set). A token Supabase refuses is a 401, never a silent guest.
* otherwise ``X-Guest-Id: <uuid>`` -> that browser's mappings, always in the local SQLite file, never in the
  main store. On a host whose disk is wiped on restart (Render's free tier) they are gone with the restart.
* neither -> a fresh guest per request: nothing it teaches is seen again.

Everyone also reads the shared seed knowledge. With accounts off, every request shares one store, as a local
install always has.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
import uuid
from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from starlette.concurrency import run_in_threadpool

from app import config as app_config
from app.db.mappings import use_scope

_GUEST_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# sha256(token) -> (user id, checked until). A minute saves a Supabase round trip on every request.
# ponytail: per-process and unbounded until 1000 entries; a signed-out token stays accepted for up to a minute.
_VERIFIED: dict[str, tuple[str, float]] = {}
_TTL = 60.0


def accounts_enabled() -> bool:
    return bool(app_config.settings.supabase_url.strip())


def verify_token(token: str) -> str:
    """The Supabase user id the access token belongs to, asked of Supabase itself (works for every key type)."""
    key = hashlib.sha256(token.encode()).hexdigest()
    cached = _VERIFIED.get(key)
    if cached and cached[1] > time.monotonic():
        return cached[0]
    settings = app_config.settings
    request = urllib.request.Request(
        f"{settings.supabase_url.strip().rstrip('/')}/auth/v1/user",
        headers={"Authorization": f"Bearer {token}", "apikey": settings.supabase_anon_key.strip()},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            user_id = json.load(response)["id"]
    except urllib.error.HTTPError as e:
        if 400 <= e.code < 500:
            raise HTTPException(401, "Your sign-in has expired: sign in again") from e
        raise HTTPException(503, "The sign-in service is not answering: try again shortly") from e
    except (OSError, ValueError, KeyError) as e:
        raise HTTPException(503, "The sign-in service is not answering: try again shortly") from e
    if len(_VERIFIED) >= 1000:
        _VERIFIED.clear()
    _VERIFIED[key] = (user_id, time.monotonic() + _TTL)
    return user_id


async def caller_scope(authorization: Optional[str] = Header(None),
                       x_guest_id: Optional[str] = Header(None)) -> None:
    """Route dependency: scope this request's mapping store to its caller.

    Async on purpose: a ContextVar set here reaches the endpoint (sync endpoints run in a copy of this context).
    """
    if not accounts_enabled():
        return
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        user_id = await run_in_threadpool(verify_token, token.strip())
        use_scope(f"user:{user_id}")
        return
    guest = (x_guest_id or "").strip().lower()
    if not _GUEST_ID.match(guest):
        guest = str(uuid.uuid4())
    use_scope(f"guest:{guest}", app_config.settings.adaptive_db_path)


router = APIRouter()


@router.get("/account/config")
async def account_config():
    """What the browser needs to offer sign-in. The anon key is public by design; access is the token's."""
    settings = app_config.settings
    if not accounts_enabled():
        return {"accounts": False}
    return {"accounts": True, "supabase_url": settings.supabase_url.strip().rstrip("/"),
            "supabase_anon_key": settings.supabase_anon_key.strip()}
