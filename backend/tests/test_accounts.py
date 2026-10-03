"""Accounts (app.auth): each account and each guest browser reads only its own taught knowledge plus the seeds."""

import asyncio
import io
import urllib.error

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app.config as app_config
from app import auth
from app.adaptive.matcher import EXTRACTION_TEMPLATE_CAPTURE
from app.db.mappings import (
    SOURCE_SEED, LearnedMapping, MappingNotFoundError, MappingPermissionError, MappingRepository, _SCOPE,
)
from app.main import app

client = TestClient(app)
GUEST = "0b9e6a52-3c1d-4e8f-9a7b-2f4c6d8e0a1b"


def _mapping(**overrides) -> LearnedMapping:
    values = dict(
        concept="ssh_protocol_version",
        normalized_field="management.ssh_version",
        command_pattern="secure-shell protocol-version {value}",
        extraction_method=EXTRACTION_TEMPLATE_CAPTURE,
        confirmed=True,
        example_line="secure-shell protocol-version 1",
    )
    values.update(overrides)
    return LearnedMapping(**values)


@pytest.fixture
def accounts_on(monkeypatch):
    monkeypatch.setattr(app_config.settings, "supabase_url", "https://example.supabase.co")
    monkeypatch.setattr(app_config.settings, "supabase_anon_key", "public-anon-key")
    tokens = {"token-a": "aaaa", "token-b": "bbbb"}

    def verify(token):
        if token not in tokens:
            raise HTTPException(401, "Your sign-in has expired: sign in again")
        return tokens[token]
    monkeypatch.setattr(auth, "verify_token", verify)


def _patterns(response) -> set[str]:
    assert response.status_code == 200, response.text
    return {m["command_pattern"] for m in response.json()}


def test_each_owner_sees_its_own_mappings_and_the_seeds():
    a, b = MappingRepository(owner="user:a"), MappingRepository(owner="user:b")
    mine = a.save_mapping(_mapping())
    MappingRepository(owner="").save_mapping(_mapping(command_pattern="ssh version {value}",
                                                      example_line="ssh version 1", source=SOURCE_SEED))

    assert {m.command_pattern for m in a.list_mappings()} == {mine.command_pattern, "ssh version {value}"}
    assert {m.command_pattern for m in b.list_mappings()} == {"ssh version {value}"}
    # the same pattern taught by another account is not a conflict: B never learns A has it
    b.save_mapping(_mapping())
    with pytest.raises(MappingNotFoundError):
        b.update_mapping(mine.id, {"active": False}, actor="admin")


def test_an_account_cannot_change_shared_knowledge():
    seed = MappingRepository(owner="").save_mapping(_mapping(source=SOURCE_SEED))
    with pytest.raises(MappingPermissionError):
        MappingRepository(owner="user:a").disable_mapping(seed.id, actor="admin")


def test_knowledge_taught_before_accounts_is_hidden_from_every_account():
    MappingRepository(owner="").save_mapping(_mapping())
    assert MappingRepository(owner="user:a").list_mappings() == []
    assert len(MappingRepository().list_mappings()) == 1


def test_rejections_are_per_owner():
    a, b = MappingRepository(owner="user:a"), MappingRepository(owner="user:b")
    a.record_rejection("frobnicate level 3")
    b.record_rejection("frobnicate level 3")  # its own row, not a clash with A's
    assert a.is_rejected("frobnicate level 3") and b.is_rejected("frobnicate level 3")
    assert not MappingRepository(owner="user:c").is_rejected("frobnicate level 3")


def test_accounts_off_is_one_shared_store():
    MappingRepository().save_mapping(_mapping())
    assert client.get("/api/account/config").json() == {"accounts": False}
    assert len(_patterns(client.get("/api/adaptive/mappings"))) == 1


def test_signed_in_requests_read_only_their_account(accounts_on):
    MappingRepository(owner="user:aaaa").save_mapping(_mapping())
    seen_by_a = _patterns(client.get("/api/adaptive/mappings", headers={"Authorization": "Bearer token-a"}))
    seen_by_b = _patterns(client.get("/api/adaptive/mappings", headers={"Authorization": "Bearer token-b"}))
    seen_by_guest = _patterns(client.get("/api/adaptive/mappings", headers={"X-Guest-Id": GUEST}))
    assert seen_by_a == {"secure-shell protocol-version {value}"}
    assert seen_by_b == seen_by_guest == set()


def test_a_refused_token_is_401_not_a_guest(accounts_on):
    response = client.get("/api/adaptive/mappings", headers={"Authorization": "Bearer stolen"})
    assert response.status_code == 401


def test_account_config_gives_the_public_key_only(accounts_on):
    assert client.get("/api/account/config").json() == {
        "accounts": True, "supabase_url": "https://example.supabase.co", "supabase_anon_key": "public-anon-key"}


def test_guest_knowledge_stays_in_the_local_file_even_with_a_main_database(accounts_on, monkeypatch):
    monkeypatch.setattr(app_config.settings, "database_url", "postgresql://never-used")

    async def scope(guest, authorization=None):
        await auth.caller_scope(authorization, guest)
        return _SCOPE.get()

    assert asyncio.run(scope(GUEST.upper())) == (f"guest:{GUEST}", app_config.settings.adaptive_db_path)
    # no (or a malformed) id: a guest of its own, never someone else's
    first, second = asyncio.run(scope(None)), asyncio.run(scope("../../etc"))
    assert first[0].startswith("guest:") and first[0] != second[0]
    assert asyncio.run(scope(None, "Bearer token-a"))[0] == "user:aaaa"


def test_supabase_refusal_is_401_and_an_outage_is_503(monkeypatch):
    monkeypatch.setattr(app_config.settings, "supabase_url", "https://example.supabase.co")

    def refuse(code):
        def urlopen(request, timeout):
            raise urllib.error.HTTPError(request.full_url, code, "no", {}, io.BytesIO(b""))
        return urlopen

    monkeypatch.setattr(auth.urllib.request, "urlopen", refuse(403))
    with pytest.raises(HTTPException) as e:
        auth.verify_token("expired")
    assert e.value.status_code == 401
    monkeypatch.setattr(auth.urllib.request, "urlopen", refuse(502))
    with pytest.raises(HTTPException) as e:
        auth.verify_token("whatever")
    assert e.value.status_code == 503
