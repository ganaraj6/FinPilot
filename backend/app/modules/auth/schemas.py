"""Pydantic schemas for the auth module.

Email fields only validate format here; lowercase normalization is handled by
the auth service layer, not by the schemas.
"""

from __future__ import annotations

from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, EmailStr, Field, field_validator

_BCRYPT_MAX_PASSWORD_BYTES = 72


def _validate_password_bcrypt_compatible(value: str) -> str:
    """Reject passwords that exceed bcrypt's 72-byte input limit.

    bcrypt silently truncates anything past 72 bytes, which would let two
    different passwords produce the same hash. The limit is enforced on the way
    in so the caller gets a 422 instead of a truncated hash. Every schema that
    accepts a new plaintext password routes through this one rule.

    Args:
        value: The plaintext password to check.

    Returns:
        The unchanged password when it fits.

    Raises:
        ValueError: If the UTF-8 encoding exceeds bcrypt's limit.
    """
    if len(value.encode("utf-8")) > _BCRYPT_MAX_PASSWORD_BYTES:
        raise ValueError(f"password must not exceed {_BCRYPT_MAX_PASSWORD_BYTES} UTF-8 bytes")
    return value


class UserRegistrationRequest(BaseModel):
    """Request payload for registering a new user account."""

    full_name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=1)

    @field_validator("password")
    @classmethod
    def validate_password_bcrypt_compatible(cls, value: str) -> str:
        """Reject passwords that exceed bcrypt's 72-byte input limit."""
        return _validate_password_bcrypt_compatible(value)


class UserLoginRequest(BaseModel):
    """Request payload for authenticating an existing user."""

    email: EmailStr
    password: str = Field(min_length=1)


class ForgotPasswordRequest(BaseModel):
    """Request payload for asking for a password-reset link.

    Only the email is accepted. The response is identical whether or not the
    address belongs to an account, so the schema carries nothing that would let
    a caller confirm that an account exists.
    """

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Request payload for redeeming a password-reset token.

    The opaque reset token is the only accepted credential: no user id is
    accepted alongside it, so the stored token record alone identifies which
    account is reset.
    """

    token: str = Field(min_length=1)
    new_password: str = Field(min_length=1)

    @field_validator("new_password")
    @classmethod
    def validate_new_password_bcrypt_compatible(cls, value: str) -> str:
        """Apply the shared bcrypt input limit to the new password."""
        return _validate_password_bcrypt_compatible(value)


class MessageResponse(BaseModel):
    """Generic single-message response for endpoints with no payload to return.

    Reused for password-reset flows, which have no profile or record to return
    and must not echo the opaque reset token back to the caller.
    """

    message: str


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
