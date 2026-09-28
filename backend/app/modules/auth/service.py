"""Authentication business logic for the auth module.

AuthService implements user registration, credential authentication, and the
password-reset foundation. It depends only on its repositories, the password
security utilities, the password-reset token utilities, and the database
session. It raises application exceptions (app.core.exceptions) that the
eventual router translates into HTTP responses; it never touches FastAPI,
JWT, or cookies.

Concurrent duplicate registrations are reconciled with the database unique
constraint, and login serializes authentication-state updates by locking the
user row for the duration of the transaction. Password reset locks both the
reset-token row and the user row, and commits the password update, the token
consumption, and the clearing of lockout state as one atomic unit.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config.settings import Settings, get_settings
from app.core.exceptions import (
    AccountLockedError,
    EmailAlreadyRegisteredError,
    ExpiredPasswordResetTokenError,
    InactiveAccountError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    UsedPasswordResetTokenError,
)
from app.core.reset_tokens import generate_password_reset_token, hash_password_reset_token
from app.core.security import hash_password, verify_password
from app.modules.auth.models import PasswordResetToken, User
from app.modules.auth.repository import PasswordResetTokenRepository, UserRepository
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

    def __init__(
        self,
        db: Session,
        repository: UserRepository,
        reset_token_repository: PasswordResetTokenRepository | None = None,
        settings: Settings | None = None,
    ) -> None:
        """Initialize the service with a session and its collaborators.

        Args:
            db: Database session. The repositories perform the writes; the
                service owns the transaction boundary (commit) for each
                logical operation.
            repository: Repository for all User persistence.
            reset_token_repository: Repository for password-reset token
                persistence. Defaults to a repository bound to the same session
                so existing two-argument construction keeps working.
            settings: Application settings supplying the reset-token lifetime.
                Defaults to the cached application settings.
        """
        self._db = db
        self._repository = repository
        self._reset_token_repository = (
            reset_token_repository
            if reset_token_repository is not None
            else PasswordResetTokenRepository(db)
        )
        self._settings = settings if settings is not None else get_settings()

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

    def create_password_reset_token(self, email: str) -> str | None:
        """Issue a new password-reset token for the user with the given email.

        Every previously issued but still-unused token for the same user is spent
        in the same transaction, so only the most recently requested reset link
        can ever be redeemed. Only the token's SHA-256 digest is persisted; the
        raw token is returned to the caller, which owns delivering it to the
        user through the future email layer.

        Args:
            email: The email address to issue a token for. It is normalized
                through the same path as registration and login.

        Returns:
            The raw reset token to deliver, or None when no account has that
            email. Returning None rather than raising lets the future HTTP layer
            answer existing and unknown addresses identically, which prevents
            account enumeration.
        """
        user = self._repository.get_by_email(self._normalize_email(email))
        if user is None:
            return None

        raw_token = generate_password_reset_token()
        now = self._utcnow()
        try:
            self._reset_token_repository.invalidate_unused_for_user(user.id, now)
            self._reset_token_repository.create(
                PasswordResetToken(
                    user_id=user.id,
                    token_hash=hash_password_reset_token(raw_token),
                    expires_at=now
                    + timedelta(minutes=self._settings.password_reset_token_expire_minutes),
                )
            )
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        return raw_token

    def validate_password_reset_token(
        self, token: str, *, for_update: bool = False
    ) -> PasswordResetToken:
        """Return the stored reset token for a submitted token if it is usable.

        The submitted token is hashed and looked up by digest, so the raw token
        is never compared against or recovered from storage. Expiry and
        consumption state are evaluated here rather than in the repository,
        which stays limited to persistence.

        The three failure modes raise distinct domain errors so callers can tell
        them apart internally. A future HTTP layer may deliberately collapse
        them into one indistinguishable response.

        Args:
            token: The raw reset token as delivered to the user.
            for_update: Whether to lock the token row (SELECT ... FOR UPDATE)
                for the remainder of the current transaction, so concurrent
                redemptions of the same token serialize.

        Returns:
            The usable reset token record. Its ``user_id`` is the sole
            authority on which account the token belongs to.

        Raises:
            InvalidPasswordResetTokenError: If no stored digest matches.
            ExpiredPasswordResetTokenError: If the token is past its expiry.
            UsedPasswordResetTokenError: If the token was already consumed or
                superseded by a newer token.
        """
        return self._resolve_password_reset_token(token, now=self._utcnow(), for_update=for_update)

    def reset_password(self, token: str, new_password: str) -> None:
        """Redeem a password-reset token and replace the account's password.

        The stored record alone determines which account is reset, so no user
        identifier is accepted from the caller and a token can never be redeemed
        against a different account. The new password is bcrypt-hashed here and
        is never stored in plaintext.

        The password update, the token consumption, and the clearing of
        lockout state are committed as one transaction: if any part fails,
        everything is rolled back and the token remains usable. ``last_login_at``
        is deliberately not touched and no access or refresh token is issued,
        because a password reset is not a login; the user authenticates normally
        afterwards.

        Args:
            token: The raw reset token as delivered to the user.
            new_password: The new plaintext password.

        Raises:
            InvalidPasswordResetTokenError: If the token matches no stored
                digest, or its account no longer exists or is inactive.
            ExpiredPasswordResetTokenError: If the token is past its expiry.
            UsedPasswordResetTokenError: If the token was already consumed or
                superseded by a newer token.
        """
        now = self._utcnow()

        # The whole operation is transactional, so the rollback handler must span
        # every step that can fail. Token resolution takes the token row lock and
        # password hashing can raise, so both sit inside the ``try``; otherwise an
        # early failure would escape without rolling back and would leave the lock
        # held until the session is closed.
        try:
            record = self._resolve_password_reset_token(token, now=now, for_update=True)

            # Hashed after the token row lock but before the user row is locked, so
            # bcrypt's cost is never paid while holding that lock. A rejected
            # password therefore also never reaches the writes below and can never
            # consume the token.
            new_password_hash = hash_password(new_password)

            user = self._repository.get_by_id(record.user_id, for_update=True)
            if user is None or not user.is_active:
                raise InvalidPasswordResetTokenError()
            self._repository.update_password(user, new_password_hash)
            self._repository.update_authentication_state(
                user,
                failed_login_attempts=0,
                locked_until=None,
            )
            self._reset_token_repository.mark_used(record, now)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def _resolve_password_reset_token(
        self, token: str, *, now: datetime, for_update: bool
    ) -> PasswordResetToken:
        """Return the usable reset token matching the submitted token.

        Shared by the public validation method and by the reset operation so
        both apply exactly the same lookup and state rules. Expiry is compared
        against ``expires_at`` as a timezone-aware instant; a token whose expiry
        has just passed is already unusable.
        """
        record = self._reset_token_repository.get_by_token_hash(
            hash_password_reset_token(token), for_update=for_update
        )
        if record is None:
            raise InvalidPasswordResetTokenError()
        if record.used_at is not None:
            raise UsedPasswordResetTokenError()
        if record.expires_at <= now:
            raise ExpiredPasswordResetTokenError()
        return record

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
