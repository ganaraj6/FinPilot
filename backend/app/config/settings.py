"""Application settings loaded from environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed access to all application configuration values."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "FinPilot"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = True
    api_v1_prefix: str = "/api/v1"
    database_url: str = "postgresql+psycopg://finpilot:finpilot@localhost:5432/finpilot"


@lru_cache
def get_settings() -> Settings:
    """Return a cached instance of the application settings."""
    return Settings()
