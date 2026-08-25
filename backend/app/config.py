from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    app_name: str = "NetAuditAI"
    debug: bool = True

    gemini_api_key: str = ""

    # Where uploaded configs are temporarily stored
    upload_dir: Path = Path("uploads")

    # Max config file size (2MB should be more than enough)
    max_file_size: int = 2 * 1024 * 1024

    class Config:
        env_file = ".env"


settings = Settings()
settings.upload_dir.mkdir(exist_ok=True)
