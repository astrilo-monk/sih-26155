from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


# Resolve .env relative to the backend directory (two levels up from this file:
# app/config.py -> backend/app/ -> backend/). This ensures the .env file
# is found regardless of whether the server is started from the repo root
# or the backend directory.
_BACKEND_DIR = Path(__file__).resolve().parent.parent
_ENV_FILE = _BACKEND_DIR / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        extra="ignore",
    )

    app_name: str = "NetAuditAI"
    debug: bool = True

    groq_api_key: str = ""
    groq_api_key_1: str = ""
    groq_api_key_2: str = ""
    groq_api_key_3: str = ""
    groq_api_key_4: str = ""

    # Where uploaded configs are temporarily stored
    upload_dir: Path = _BACKEND_DIR / "uploads"

    # Max config file size (2MB should be more than enough)
    max_file_size: int = 2 * 1024 * 1024

    # SQLite database holding administrator-confirmed adaptive mappings
    adaptive_db_path: Path = _BACKEND_DIR / "data" / "adaptive.db"

    # LEGACY, isolated: send lines the Cisco/FortiGate parsers do not read to the line-by-line interpreter
    # (app.adaptive.interpreter). The Phase 7 judge never escalates confirmed vendors, so it cannot replace this
    # yet. Off by default; when on, every interpretation goes to the review queue and is never applied without
    # an administrator (AdaptiveService), so it cannot change any result, score, finding or coverage.
    adaptive_ai_for_known_vendors: bool = False

    # Share of meaningful lines that must follow the detected vendor's grammar
    # before its profile (parser, vendor-specific rules) is trusted. Below it
    # the config is UNVERIFIED and takes the unknown-vendor path.
    vendor_parse_coverage_threshold: float = 0.7

    # Phase 7: the AI judges only UNKNOWN controls of unknown-vendor configs, at most this many
    # calls per scan (cache hits are free)
    ai_judge_max_calls_per_scan: int = 2


settings = Settings()
settings.upload_dir.mkdir(exist_ok=True)
