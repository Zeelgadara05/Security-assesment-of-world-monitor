"""Centralised application configuration.

Reads configuration from environment variables (optionally loaded from a
``.env`` file via python-dotenv).  Nothing in this module is secret by
construction -- real credentials/keys must never be placed here.

Environment variables consumed:
  DATABASE_URL   SQLAlchemy database URL.            Default: sqlite:///./cyberagent.db
  SIMULATION_MODE Whether scans run in simulation.    Default: true
  CORS_ORIGINS   Comma separated allowed CORS origins. Default: local dev Vite origins
  REDIS_URL      Broker URL (reserved for future Celery use). Default: redis://localhost:6379/0
"""
import os

from dotenv import load_dotenv

# Load variables from a .env file (if present). Existing process environment
# variables always win because python-dotenv does not override by default.
load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class Settings:
    def __init__(self) -> None:
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./cyberagent.db")
        self.simulation_mode = _env_bool("SIMULATION_MODE", True)
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

        # Preserve only origins actually required by the current frontend.
        # CORS_ORIGINS overrides the development defaults when provided.
        raw_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
        self.cors_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]


settings = Settings()