"""Pydantic schemas for the auth module.

Email fields only validate format here; lowercase normalization is handled by
the auth service layer, not by the schemas.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, EmailStr, Field, field_validator

_BCRYPT_MAX_PASSWORD_BYTES = 72


class UserRegistrationRequest(BaseModel):
    """Request payload for registering a new user account."""

    full_name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=1)

    @field_validator("password")
    @classmethod
    def validate_password_bcrypt_compatible(cls, value: str) -> str:
        """Reject passwords that exceed bcrypt's 72-byte input limit."""
        if len(value.encode("utf-8")) > _BCRYPT_MAX_PASSWORD_BYTES:
            raise ValueError(f"password must not exceed {_BCRYPT_MAX_PASSWORD_BYTES} UTF-8 bytes")
        return value


class UserLoginRequest(BaseModel):
    """Request payload for authenticating an existing user."""

    email: EmailStr
    password: str = Field(min_length=1)


class AuthenticatedUserResponse(BaseModel):
    """Safe user profile returned after successful authentication."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    full_name: str
    email: EmailStr
    profile_photo_url: str | None
    currency: str
    timezone: str
    onboarding_completed: bool
    is_active: bool
    email_verified_at: AwareDatetime | None
    created_at: AwareDatetime
