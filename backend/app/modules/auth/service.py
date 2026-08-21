"""Authentication business logic for the auth module.

AuthService implements user registration and credential authentication. It
depends only on the user repository, the password security utilities, and the
database session. It raises application exceptions (app.core.exceptions) that
the eventual router translates into HTTP responses; it never touches FastAPI,
JWT, or cookies.

Concurrent duplicate registrations are reconciled with the database unique
constraint, and login serializes authentication-state updates by locking the
user row for the duration of the transaction.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.exceptions import (
    AccountLockedError,
    EmailAlreadyRegisteredError,
    InactiveAccountError,
    InvalidCredentialsError,
)
from app.core.security import hash_password, verify_password
from app.modules.auth.models import User
from app.modules.auth.repository import UserRepository
from app.modules.auth.schemas import (
    AuthenticatedUserResponse,
    UserLoginRequest,
    UserRegistrationRequest,
)
from app.services.base import BaseService

MAX_FAILED_LOGIN_ATTEMPTS = 5
"""Maximum consecutive failed logins before an account is locked."""

LOCKOUT_DURATION_MINUTES = 15
"""How long an account stays locked after reaching the failure limit."""

EMAIL_UNIQUE_CONSTRAINT_NAME = "uq_users_email"
"""Name of the PostgreSQL unique constraint protecting users.email."""


class AuthService(BaseService):
    """Registration and credential authentication business logic."""

    def __init__(self, db: Session, repository: UserRepository) -> None:
        """Initialize the service with a session and the user repository.

        Args:
            db: Database session. The repository performs the writes; the
                service owns the transaction boundary (commit) for each
                logical operation.
            repository: Repository for all User persistence.
        """
        self._db = db
        self._repository = repository

    def get_user_for_access(self, user_id: UUID) -> User:
        """Load a user for access-token validation, raising if missing or inactive.

        The same generic error is raised for nonexistent and inactive users
        so callers cannot distinguish the two cases. ``locked_until`` is
        intentionally ignored: a locked account is still considered
        authenticated for the lifetime of its access token.

        Args:
            user_id: The UUID extracted from the validated access token.

        Returns:
            The active user entity.

        Raises:
            InvalidCredentialsError: If the user does not exist or is inactive.
        """
        user = self._repository.get_by_id(user_id)
        if user is None or not user.is_active:
            raise InvalidCredentialsError()
        return user

    def get_user_for_refresh(self, user_id: UUID) -> User:
        """Load a user for token refresh, raising if missing or inactive.

        The same generic error is raised for nonexistent and inactive users
        so callers cannot distinguish the two cases.

        Args:
            user_id: The UUID extracted from the validated refresh token.

        Returns:
            The active user entity.

        Raises:
            InvalidCredentialsError: If the user does not exist or is inactive.
        """
        user = self._repository.get_by_id(user_id)
        if user is None or not user.is_active:
            raise InvalidCredentialsError()
        return user

    def service_name(self) -> str:
        """Return the canonical service name for this module."""
        return "auth"

    def register(self, request: UserRegistrationRequest) -> AuthenticatedUserResponse:
        """Create a new user account and return its safe profile.

        The email is normalized, duplicates are rejected, and the password is
        hashed before the user is persisted. The transaction is committed once.
        A concurrent duplicate insert is detected through the database unique
        constraint and converted to the same domain error.

        Args:
            request: Registration payload with full name, email, and password.

        Returns:
            A safe user profile; sensitive fields are never returned.

        Raises:
            EmailAlreadyRegisteredError: If the normalized email is already
                registered.
        """
        email = self._normalize_email(request.email)
        if self._repository.exists_by_email(email):
            raise EmailAlreadyRegisteredError()

        user = User(
            full_name=request.full_name,
            email=email,
            password_hash=hash_password(request.password),
        )
        try:
            created_user = self._repository.create(user)
            self._db.commit()
        except IntegrityError as exc:
            self._db.rollback()
            if self._is_duplicate_email(exc):
                raise EmailAlreadyRegisteredError() from exc
            raise
        return AuthenticatedUserResponse.model_validate(created_user)

    def login(self, request: UserLoginRequest) -> AuthenticatedUserResponse:
        """Authenticate a user with email and password.

        Nonexistent users and incorrect passwords produce the same generic
        failure. Account status and lock state are checked before the password
        is verified. The user row is locked (SELECT ... FOR UPDATE) for the
        duration of the transaction so concurrent failed-login counters and
        lock updates are serialized. A failed attempt increments the failure
        counter and locks the account once the configured maximum is reached. A
        successful login resets the counter, clears any lock, and records the
        login time.

        Args:
            request: Login payload with email and password.

        Returns:
            A safe user profile; sensitive fields are never returned.

        Raises:
            InvalidCredentialsError: For nonexistent users or incorrect
                passwords.
            InactiveAccountError: If the account is deactivated.
            AccountLockedError: If the account is currently locked.
        """
        email = self._normalize_email(request.email)
        user = self._repository.get_by_email(email, for_update=True)
        if user is None:
            raise InvalidCredentialsError()

        now = self._utcnow()

        if not user.is_active:
            raise InactiveAccountError()

        if user.locked_until is not None and user.locked_until > now:
            raise AccountLockedError()

        if not verify_password(request.password, user.password_hash):
            self._record_failed_login(user, now)
            self._db.commit()
            raise InvalidCredentialsError()

        self._repository.update_authentication_state(
            user,
            last_login_at=now,
            failed_login_attempts=0,
            locked_until=None,
        )
        self._db.commit()
        return AuthenticatedUserResponse.model_validate(user)

    def _record_failed_login(self, user: User, now: datetime) -> None:
        """Increment the failure counter, locking the account at the limit.

        The counter is retained (not reset) when the account is locked. The
        caller commits the change so each logical operation commits once. The
        increment is safe against concurrent attempts because login holds the
        user row lock for the duration of the transaction.

        Args:
            user: The user that failed authentication.
            now: Current UTC time used to compute the lock expiry.
        """
        failed_login_attempts = user.failed_login_attempts + 1
        if failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            self._repository.update_authentication_state(
                user,
                failed_login_attempts=failed_login_attempts,
                locked_until=now + timedelta(minutes=LOCKOUT_DURATION_MINUTES),
            )
        else:
            self._repository.update_authentication_state(
                user,
                failed_login_attempts=failed_login_attempts,
            )

    @staticmethod
    def _is_duplicate_email(error: IntegrityError) -> bool:
        """Return whether the integrity error is the users.email unique violation.

        Uses the PostgreSQL constraint diagnostic when available and falls back
        to the driver message. Only a positively identified duplicate email is
        reported as such; anything else is left for the caller to re-raise.

        Args:
            error: The IntegrityError raised by the registration insert.

        Returns:
            True if the error is a duplicate users.email violation.
        """
        orig = getattr(error, "orig", None)
        diag = getattr(orig, "diag", None)
        constraint_name = getattr(diag, "constraint_name", None)
        if constraint_name is not None:
            return constraint_name == EMAIL_UNIQUE_CONSTRAINT_NAME
        message = str(orig) if orig is not None else str(error)
        return (
            "duplicate key value violates unique constraint" in message
            and f'"{EMAIL_UNIQUE_CONSTRAINT_NAME}"' in message
        )

    @staticmethod
    def _normalize_email(email: str) -> str:
        """Strip surrounding whitespace and lowercase the given email.

        Registration and login share this single normalization path so they
        behave identically. For example, " User@Example.COM " becomes
        "user@example.com".
        """
        return email.strip().lower()

    @staticmethod
    def _utcnow() -> datetime:
        """Return the current time as a timezone-aware UTC datetime."""
        return datetime.now(UTC)
