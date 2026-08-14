"""JWT access and refresh token management for FinPilot.

This module is the single security component responsible for creating, decoding,
and validating signed JWT tokens. It is intentionally independent of FastAPI
routes, databases, repositories, and services: it performs no I/O and only does
cryptographic token operations. All signing configuration comes from the
application settings.

Tokens are signed with an explicitly configured symmetric algorithm (never
"none") and carry only minimal claims: sub (user UUID), exp, iat, jti, and
token_type. Raw PyJWT exceptions are translated into the application exception
hierarchy so the rest of the application never sees library internals. Tokens
and signing secrets are never logged.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from functools import lru_cache
from uuid import UUID

import jwt
from pydantic import AwareDatetime, BaseModel

from app.config.settings import Settings, get_settings
from app.core.exceptions import (
    ExpiredTokenError,
    InvalidTokenError,
    InvalidTokenTypeError,
)


class TokenType(StrEnum):
    """The kind of token, distinguishing access from refresh tokens."""

    ACCESS = "access"
    REFRESH = "refresh"


class TokenClaims(BaseModel):
    """Validated claims extracted from a decoded token.

    Instances are produced only after signature, expiration, subject, and type
    validation; the application never works with raw token payloads.
    """

    user_id: UUID
    token_type: TokenType
    jti: str
    issued_at: AwareDatetime
    expires_at: AwareDatetime


class TokenService:
    """Creates and validates signed JWT access and refresh tokens.

    All cryptographic configuration (secret, algorithm, lifetimes) comes from
    the injected settings. The service performs no I/O and holds no state other
    than the settings it was constructed with.
    """

    def __init__(self, settings: Settings) -> None:
        """Store the settings that drive all token operations.

        Args:
            settings: Application settings containing the JWT configuration.
        """
        self._settings = settings
        self._secret = settings.jwt_secret_key.get_secret_value()
        self._algorithm = settings.jwt_algorithm

    def create_access_token(self, user_id: UUID) -> str:
        """Create a signed access token for the given user.

        Args:
            user_id: The user's UUID, used as the token subject.

        Returns:
            A signed JWT access token string.
        """
        return self._create_token(user_id, TokenType.ACCESS)

    def create_refresh_token(self, user_id: UUID) -> str:
        """Create a signed refresh token for the given user.

        Args:
            user_id: The user's UUID, used as the token subject.

        Returns:
            A signed JWT refresh token string.
        """
        return self._create_token(user_id, TokenType.REFRESH)

    def decode_token(self, token: str) -> TokenClaims:
        """Decode and validate a token without enforcing a specific type.

        Verifies the signature, expiration, required claims, subject format,
        issued-at value, and token type value. See validate_access_token and
        validate_refresh_token to additionally enforce the token type.

        Args:
            token: The JWT string to decode.

        Returns:
            The validated typed claims.

        Raises:
            ExpiredTokenError: If the token has expired.
            InvalidTokenError: If the token is malformed, tampered, or fails
                any claim validation.
        """
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "require": ["sub", "exp", "iat", "jti", "token_type"],
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise ExpiredTokenError() from exc
        except jwt.PyJWTError as exc:
            raise InvalidTokenError() from exc

        claims = TokenClaims(
            user_id=self._parse_subject(payload["sub"]),
            token_type=self._parse_token_type(payload["token_type"]),
            jti=self._parse_jti(payload["jti"]),
            issued_at=self._parse_timestamp(payload["iat"]),
            expires_at=self._parse_timestamp(payload["exp"]),
        )
        self._validate_issued_at(claims.issued_at)
        return claims

    def validate_access_token(self, token: str) -> TokenClaims:
        """Decode a token and require that it is an access token.

        Args:
            token: The JWT string to validate.

        Returns:
            The validated typed claims.

        Raises:
            InvalidTokenTypeError: If the token is not an access token.
            ExpiredTokenError: If the token has expired.
            InvalidTokenError: If the token fails any other validation.
        """
        claims = self.decode_token(token)
        if claims.token_type is not TokenType.ACCESS:
            raise InvalidTokenTypeError()
        return claims

    def validate_refresh_token(self, token: str) -> TokenClaims:
        """Decode a token and require that it is a refresh token.

        Args:
            token: The JWT string to validate.

        Returns:
            The validated typed claims.

        Raises:
            InvalidTokenTypeError: If the token is not a refresh token.
            ExpiredTokenError: If the token has expired.
            InvalidTokenError: If the token fails any other validation.
        """
        claims = self.decode_token(token)
        if claims.token_type is not TokenType.REFRESH:
            raise InvalidTokenTypeError()
        return claims

    def _create_token(self, user_id: UUID, token_type: TokenType) -> str:
        """Build and sign a JWT carrying the minimal required claims."""
        now = datetime.now(UTC)
        if token_type is TokenType.ACCESS:
            lifetime = timedelta(minutes=self._settings.access_token_expire_minutes)
        else:
            lifetime = timedelta(minutes=self._settings.refresh_token_expire_minutes)
        payload = {
            "sub": str(user_id),
            "token_type": token_type.value,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + lifetime,
        }
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    @staticmethod
    def _parse_subject(subject: object) -> UUID:
        """Validate the sub claim and return it as a UUID.

        Args:
            subject: The raw sub claim value.

        Returns:
            The validated user UUID.

        Raises:
            InvalidTokenError: If the subject is not a valid UUID string.
        """
        if not isinstance(subject, str):
            raise InvalidTokenError()
        try:
            return UUID(subject)
        except (ValueError, AttributeError, TypeError) as exc:
            raise InvalidTokenError() from exc

    @staticmethod
    def _parse_token_type(value: object) -> TokenType:
        """Validate the token_type claim against the known token types.

        Args:
            value: The raw token_type claim value.

        Returns:
            The corresponding TokenType.

        Raises:
            InvalidTokenError: If the value is not a known token type.
        """
        try:
            return TokenType(str(value))
        except ValueError as exc:
            raise InvalidTokenError() from exc

    @staticmethod
    def _parse_jti(value: object) -> str:
        """Validate the jti claim and return it as a string.

        Args:
            value: The raw jti claim value.

        Returns:
            The validated token identifier.

        Raises:
            InvalidTokenError: If the value is missing or empty.
        """
        if not isinstance(value, str) or not value:
            raise InvalidTokenError()
        return value

    @staticmethod
    def _parse_timestamp(value: object) -> datetime:
        """Validate a Unix timestamp claim and return an aware UTC datetime.

        Args:
            value: The raw numeric timestamp claim value.

        Returns:
            A timezone-aware UTC datetime.

        Raises:
            InvalidTokenError: If the value is not a valid numeric timestamp.
        """
        if not isinstance(value, (int, float)):
            raise InvalidTokenError()
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise InvalidTokenError() from exc

    @staticmethod
    def _validate_issued_at(issued_at: datetime) -> None:
        """Reject an issued-at time that lies in the future.

        Tokens are issued and verified by the same service, so the issuer and
        verifier share a clock and a future iat can only indicate a forged or
        tampered token. No clock-skew allowance is needed.

        Args:
            issued_at: The decoded iat claim as an aware UTC datetime.

        Raises:
            InvalidTokenError: If the issued-at time is in the future.
        """
        if issued_at > datetime.now(UTC):
            raise InvalidTokenError()


@lru_cache
def _default_token_service() -> TokenService:
    """Return a TokenService configured from the cached application settings."""
    return TokenService(get_settings())


def create_access_token(user_id: UUID) -> str:
    """Create a signed access token using the application settings.

    Args:
        user_id: The user's UUID used as the token subject.

    Returns:
        A signed JWT access token string.
    """
    return _default_token_service().create_access_token(user_id)


def create_refresh_token(user_id: UUID) -> str:
    """Create a signed refresh token using the application settings.

    Args:
        user_id: The user's UUID used as the token subject.

    Returns:
        A signed JWT refresh token string.
    """
    return _default_token_service().create_refresh_token(user_id)


def decode_token(token: str) -> TokenClaims:
    """Decode and validate a token using the application settings.

    Args:
        token: The JWT string to decode.

    Returns:
        The validated typed claims.
    """
    return _default_token_service().decode_token(token)


def validate_access_token(token: str) -> TokenClaims:
    """Decode and validate an access token using the application settings.

    Args:
        token: The JWT string to validate.

    Returns:
        The validated typed claims.
    """
    return _default_token_service().validate_access_token(token)


def validate_refresh_token(token: str) -> TokenClaims:
    """Decode and validate a refresh token using the application settings.

    Args:
        token: The JWT string to validate.

    Returns:
        The validated typed claims.
    """
    return _default_token_service().validate_refresh_token(token)
