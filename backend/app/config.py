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

    # When set, every /api route requires it in an X-API-Key header. Empty = open, as the demo runs.
    api_key: str = ""
    # Origins allowed to call the API: "*" or a comma-separated list of origins
    cors_origins: str = "*"

    groq_api_key: str = ""
    groq_api_key_1: str = ""
    groq_api_key_2: str = ""
    groq_api_key_3: str = ""
    groq_api_key_4: str = ""

    # Offline AI: an OpenAI-compatible server on your own machine or network (Ollama, llama.cpp, vLLM), e.g.
    # http://localhost:11434/v1. When set it replaces Groq entirely; nothing leaves the network. Empty = Groq.
    local_ai_url: str = ""
    local_ai_model: str = "llama3.1:8b"
    # Local models are slower than Groq: every call gets at least this many seconds
    local_ai_timeout: float = 120.0

    # Where uploaded configs are temporarily stored
    upload_dir: Path = _BACKEND_DIR / "uploads"

    # Max config file size (2MB should be more than enough)
    max_file_size: int = 2 * 1024 * 1024

    # SQLite database holding administrator-confirmed adaptive mappings
    adaptive_db_path: Path = _BACKEND_DIR / "data" / "adaptive.db"
    # Postgres (e.g. Supabase) instead of the SQLite file above, so learned knowledge survives a host whose disk is
    # wiped on restart. Empty = SQLite.
    database_url: str = ""

    # Accounts (app.auth): a Supabase project's URL and its public anon key, never the service-role key. Set, each
    # account keeps its own taught knowledge and a guest's lives only in the SQLite file above. Empty = no accounts,
    # one shared store.
    supabase_url: str = ""
    supabase_anon_key: str = ""

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

    # Pull configurations off live devices over SSH (app.collect) instead of uploading them. On by
    # default: it is a deliverable the workflow asks for, and Netmiko ships in requirements.txt, so an
    # operator running this locally can audit a device without exporting its configuration by hand.
    # Set it to false on a backend others can reach -the endpoint opens a session to whatever host it
    # is given, which is then a way into the network the backend sits in.
    live_collection_enabled: bool = True

    # Which hosts live collection may open a session to. "private" (the default) resolves the host and
    # allows it only inside RFC1918 space or loopback -the operator's own network, which is what the
    # feature is for. It deliberately refuses link-local (169.254.0.0/16), because that is the cloud
    # metadata endpoint and Python counts it as private. "any" lifts the restriction for an operator
    # who really must reach a device across the internet.
    live_collection_networks: str = "private"


settings = Settings()
settings.upload_dir.mkdir(exist_ok=True)
