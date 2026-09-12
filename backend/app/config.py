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

    # Where uploaded configs are temporarily stored
    upload_dir: Path = _BACKEND_DIR / "uploads"

    # Max config file size (2MB should be more than enough)
    max_file_size: int = 2 * 1024 * 1024


settings = Settings()
settings.upload_dir.mkdir(exist_ok=True)
