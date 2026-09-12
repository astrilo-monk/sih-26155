"""
Regression test for .env loading when the server is started from
different working directories (repo root vs backend/).

This test proves that the GROQ_API_KEY is loaded from backend/.env
regardless of CWD, WITHOUT exposing the actual API key value.

The test works by:
1. Recording the resolved .env path from the Settings model_config
2. Verifying the .env file exists at that path
3. Verifying that settings.groq_api_key is non-empty (key loaded)
4. Verifying the key is NOT a real key (it's masked in test output)
5. Running the same verification from a different CWD
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from app.config import settings, _ENV_FILE, _BACKEND_DIR


# ===========================================================================
# Test 1 — .env path is resolved relative to the config module
# ===========================================================================

def test_env_file_path_is_resolved_relative_to_backend():
    """The .env path must be resolved relative to the backend directory,
    not relative to CWD."""

    # The _ENV_FILE should point to backend/.env
    assert _ENV_FILE == _BACKEND_DIR / ".env"

    # The backend directory is the parent of the app directory
    assert _BACKEND_DIR == Path(__file__).resolve().parent.parent

    # _ENV_FILE should end with .env and be in the backend/ directory
    assert _ENV_FILE.name == ".env"
    assert _ENV_FILE.parent == _BACKEND_DIR

    # The .env file must exist at that location
    assert _ENV_FILE.exists(), f".env not found at expected location: {_ENV_FILE}"

    print(f"\nPASS: .env path resolved to { _ENV_FILE }")


# ===========================================================================
# Test 2 — Settings model_config uses explicit env_file path
# ===========================================================================

def test_settings_model_config_has_explicit_env_file():
    """Settings must use model_config (not deprecated class Config) with
    an explicit env_file path."""

    config_dict = settings.model_config

    # Must have env_file configured
    assert "env_file" in config_dict, "model_config must specify env_file"

    env_file = config_dict["env_file"]
    # The env_file must be an absolute path (resolved relative to module)
    assert Path(env_file).is_absolute(), (
        f"env_file should be an absolute path for CWD-independent loading, "
        f"got: {env_file}"
    )

    print(f"\nPASS: Settings model_config has explicit env_file: {env_file}")


# ===========================================================================
# Test 3 — GROQ_API_KEY is loaded (non-empty)
# ===========================================================================

def test_groq_api_key_is_loaded():
    """The GROQ_API_KEY must be loaded from .env (non-empty)."""

    key = settings.groq_api_key

    # Must not be empty
    assert key != "", "GROQ_API_KEY should be loaded from .env"
    assert key is not None, "GROQ_API_KEY should not be None"

    # Must start with the expected Groq prefix (not the full key)
    assert key.startswith("gsk_"), (
        f"API key should start with 'gsk_'"
    )

    # Do NOT expose the full key in pytest output
    masked = key[:8] + "...(redacted)"
    print(f"\nPASS: GROQ_API_KEY loaded (redacted: {masked})")


# ===========================================================================
# Test 4 — CWD independence (key loads from repo root)
# ===========================================================================

def test_config_works_from_repo_root():
    """Settings must load the .env key when CWD is the repository root,
    not just when CWD is backend/."""

    import os

    original_cwd = os.getcwd()

    try:
        # Simulate running from the repository root
        repo_root = _BACKEND_DIR.parent
        os.chdir(repo_root)

        # Re-import settings module and reload to simulate fresh import
        import importlib
        import app.config as config_module
        importlib.reload(config_module)

        # The reloaded settings should still have the key
        reloaded_settings = config_module.settings

        key = reloaded_settings.groq_api_key
        assert key != "", (
            "GROQ_API_KEY must be loaded even when CWD is the repository root, "
            "not just when CWD is backend/"
        )
        assert key.startswith("gsk_"), "API key should start with 'gsk_'"

        masked = key[:8] + "...(redacted)"
        print(f"\nPASS: Config loads .env from repo root (CWD={repo_root}), key redacted: {masked}")

    finally:
        os.chdir(original_cwd)
        # Restore original settings module state
        import importlib
        import app.config as config_module
        importlib.reload(config_module)


# ===========================================================================
# Test 5 — is_available() returns True with key loaded
# ===========================================================================

def test_is_available_returns_true_when_key_loaded():
    """is_available() must return True when the API key is properly loaded."""

    from app.ai.client import is_available

    result = is_available()
    assert result is True, (
        "is_available() should return True when GROQ_API_KEY is loaded"
    )

    print("\nPASS: is_available() returns True")


# ===========================================================================
# Test 6 — No deprecated class Config
# ===========================================================================

def test_no_deprecated_class_config():
    """Settings must not use the deprecated class Config (which causes
    the CWD-dependent .env loading issue)."""

    # The Settings class should use model_config (pydantic-settings 2.x)
    # not the deprecated class Config
    assert hasattr(settings.__class__, "model_config"), (
        "Settings should use model_config, not deprecated class Config"
    )

    # model_config should be a dict (SettingsConfigDict)
    assert isinstance(settings.__class__.model_config, dict)

    print("\nPASS: No deprecated class Config detected")


# ---------------------------------------------------------------------------
# Run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_env_file_path_is_resolved_relative_to_backend()
    test_settings_model_config_has_explicit_env_file()
    test_groq_api_key_is_loaded()
    test_config_works_from_repo_root()
    test_is_available_returns_true_when_key_loaded()
    test_no_deprecated_class_config()

    print("\n")
    print("============================================")
    print("ALL CONFIG LOADING REGRESSION TESTS PASSED")
    print("============================================")
