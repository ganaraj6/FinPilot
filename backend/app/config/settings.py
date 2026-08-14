"""Application settings loaded from environment variables."""

from functools import lru_cache
from typing import Self

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_JWT_ALGORITHMS_ALLOWED = frozenset({"HS256", "HS384", "HS512"})
_JWT_SECRET_MIN_LENGTH = 32


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

    # JWT configuration (all values come from the environment / .env file).
    jwt_secret_key: SecretStr
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_minutes: int = 60 * 24 * 14

    @field_validator("jwt_secret_key")
    @classmethod
    def _validate_jwt_secret_key(cls, value: SecretStr) -> SecretStr:
        """Require a sufficiently long secret so weak defaults are rejected."""
        if len(value.get_secret_value()) < _JWT_SECRET_MIN_LENGTH:
            raise ValueError(f"jwt_secret_key must be at least {_JWT_SECRET_MIN_LENGTH} characters")
        return value

    @field_validator("jwt_algorithm")
    @classmethod
    def _validate_jwt_algorithm(cls, value: str) -> str:
        """Restrict the signing algorithm to the approved symmetric set."""
        if value not in _JWT_ALGORITHMS_ALLOWED:
            raise ValueError(f"jwt_algorithm must be one of {sorted(_JWT_ALGORITHMS_ALLOWED)}")
        return value

    @field_validator("access_token_expire_minutes")
    @classmethod
    def _validate_access_token_expire_minutes(cls, value: int) -> int:
        """Require a positive access-token lifetime."""
        if value <= 0:
            raise ValueError("access_token_expire_minutes must be greater than 0")
        return value

    @field_validator("refresh_token_expire_minutes")
    @classmethod
    def _validate_refresh_token_expire_minutes(cls, value: int) -> int:
        """Require a positive refresh-token lifetime."""
        if value <= 0:
            raise ValueError("refresh_token_expire_minutes must be greater than 0")
        return value

    @model_validator(mode="after")
    def _validate_token_lifetimes(self) -> Self:
        """Require the refresh lifetime to exceed the access lifetime."""
        if self.refresh_token_expire_minutes <= self.access_token_expire_minutes:
            raise ValueError(
                "refresh_token_expire_minutes must be greater than access_token_expire_minutes"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return a cached instance of the application settings."""
    return Settings()
