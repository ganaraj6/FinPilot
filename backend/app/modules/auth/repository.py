"""Repository for the User entity in the auth module."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select

from app.modules.auth.models import User
from app.repositories.base import BaseRepository

_UNSET = object()


class UserRepository(BaseRepository[User]):
    """Persistence operations for the User entity used by authentication."""

    def create(self, user: User) -> User:
        """Persist a prepared user and return the refreshed entity."""
        self._db.add(user)
        self._db.flush()
        self._db.refresh(user)
        return user

    def get_by_id(self, user_id: UUID) -> User | None:
        """Return the user with the given id, or None if not found."""
        statement = select(User).where(User.id == user_id)
        return self._db.scalar(statement)

    def get_by_email(self, email: str, *, for_update: bool = False) -> User | None:
        """Return the user with the exact email, or None if not found.

        Args:
            email: The email address to look up.
            for_update: Whether to lock the matched row (SELECT ... FOR UPDATE)
                until the end of the current transaction. The auth service uses
                this during login to serialize authentication-state updates
                against concurrent attempts.

        Returns:
            The matching user entity, or None.
        """
        statement = select(User).where(User.email == email)
        if for_update:
            statement = statement.with_for_update()
        return self._db.scalar(statement)

    def exists_by_email(self, email: str) -> bool:
        """Return whether a user with the exact email exists."""
        statement = select(User.id).where(User.email == email).limit(1)
        return self._db.execute(statement).first() is not None

    def update_authentication_state(
        self,
        user: User,
        *,
        last_login_at: datetime | None = _UNSET,
        failed_login_attempts: int = _UNSET,
        locked_until: datetime | None = _UNSET,
        email_verified_at: datetime | None = _UNSET,
        is_active: bool = _UNSET,
    ) -> User:
        """Apply authentication state updates to an existing user.

        Only fields explicitly provided are changed. Pass None to clear a
        nullable field (for example, locked_until to unlock an account).

        Args:
            user: Loaded user entity to update.
            last_login_at: Timestamp of the most recent successful login.
            failed_login_attempts: New consecutive failure counter value.
            locked_until: Account lock expiry timestamp.
            email_verified_at: Timestamp the email address was verified.
            is_active: Whether the user account is active.

        Returns:
            The same user entity with the updates applied.
        """
        if last_login_at is not _UNSET:
            user.last_login_at = last_login_at
        if failed_login_attempts is not _UNSET:
            user.failed_login_attempts = failed_login_attempts
        if locked_until is not _UNSET:
            user.locked_until = locked_until
        if email_verified_at is not _UNSET:
            user.email_verified_at = email_verified_at
        if is_active is not _UNSET:
            user.is_active = is_active
        self._db.flush()
        return user
