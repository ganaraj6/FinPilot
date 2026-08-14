"""Application-level exceptions raised by the service layer.

Services raise these exceptions to signal domain violations. FastAPI routers
translate them into HTTP responses. Services must never raise FastAPI-specific
exceptions (such as HTTPException) so the business logic stays framework
independent.
"""

from __future__ import annotations


class FinPilotError(Exception):
    """Base class for all FinPilot application exceptions."""


class AuthenticationError(FinPilotError):
    """Base class for authentication domain errors."""


class EmailAlreadyRegisteredError(AuthenticationError):
    """Raised when registration uses an email address that is already registered."""


class InvalidCredentialsError(AuthenticationError):
    """Raised when the email/password combination is invalid.

    The same exception is raised for nonexistent users and incorrect passwords
    so callers cannot distinguish the two cases (no user enumeration).
    """


class AccountLockedError(AuthenticationError):
    """Raised when an account is temporarily locked after repeated failed logins."""


class InactiveAccountError(AuthenticationError):
    """Raised when a deactivated account attempts to authenticate."""


class TokenError(AuthenticationError):
    """Base class for JWT token creation and validation errors."""


class InvalidTokenError(TokenError):
    """Raised when a token is malformed, tampered, or fails claim validation."""


class ExpiredTokenError(TokenError):
    """Raised when a token's expiration time has already passed."""


class InvalidTokenTypeError(TokenError):
    """Raised when a token's type does not match the expected token type."""
