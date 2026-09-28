"""Repository for the User entity in the auth module."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select, update

from app.modules.auth.models import PasswordResetToken, User
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

    def get_by_id(self, user_id: UUID, *, for_update: bool = False) -> User | None:
        """Return the user with the given id, or None if not found.

        Args:
            user_id: The UUID of the user to load.
            for_update: Whether to lock the matched row (SELECT ... FOR UPDATE)
                until the end of the current transaction. Password reset uses
                this to serialize the password update and the clearing of
                authentication lockout state against concurrent logins.

        Returns:
            The matching user entity, or None.
        """
        statement = select(User).where(User.id == user_id)
        if for_update:
            statement = statement.with_for_update()
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

    def update_password(self, user: User, password_hash: str) -> User:
        """Replace the stored password hash for an existing user.

        Password updates are kept separate from ``update_authentication_state``
        so that authentication-state bookkeeping can never silently rewrite
        credentials, and so a password change is always an explicit call. The
        value must already be a bcrypt hash produced by
        ``app.core.security.hash_password``; this repository never hashes and
        never sees a plaintext password.

        Args:
            user: Loaded user entity to update.
            password_hash: The bcrypt hash to store as the new password.

        Returns:
            The same user entity with the new hash applied.
        """
        user.password_hash = password_hash
        self._db.flush()
        return user


class PasswordResetTokenRepository(BaseRepository[PasswordResetToken]):
    """Persistence operations for opaque password-reset tokens.

    The repository stores and locates only token digests. It deliberately holds
    no business rules: expiry and consumption state are evaluated by
    ``AuthService``, which owns the transaction boundary.
    """

    def create(self, token: PasswordResetToken) -> PasswordResetToken:
        """Persist a prepared reset token and return the refreshed entity."""
        self._db.add(token)
        self._db.flush()
        self._db.refresh(token)
        return token

    def get_by_token_hash(
        self, token_hash: str, *, for_update: bool = False
    ) -> PasswordResetToken | None:
        """Return the reset token with the exact digest, or None if not found.

        Args:
            token_hash: The hex digest of the submitted reset token.
            for_update: Whether to lock the matched row (SELECT ... FOR UPDATE)
                until the end of the current transaction. Password reset locks
                the token row so two concurrent redemptions of the same token
                serialize and only the first can observe it as unused.

        Returns:
            The matching reset token entity, or None.
        """
        statement = select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
        if for_update:
            statement = statement.with_for_update()
        return self._db.scalar(statement)

    def mark_used(self, token: PasswordResetToken, used_at: datetime) -> PasswordResetToken:
        """Record that a reset token is spent and can never be redeemed again.

        Args:
            token: Loaded reset token entity to update.
            used_at: Timezone-aware UTC timestamp marking the token as spent.

        Returns:
            The same reset token entity with the update applied.
        """
        token.used_at = used_at
        self._db.flush()
        return token

    def invalidate_unused_for_user(self, user_id: UUID, used_at: datetime) -> int:
        """Spend every still-unused reset token belonging to a user.

        This implements the "latest request wins" policy: issuing a new token
        invalidates all previous ones so that only the most recent reset link
        remains redeemable. Reusing ``used_at`` for both consumption and
        supersession keeps a single invalidation marker on the model instead of
        a second ``revoked_at`` column.

        Args:
            user_id: The user whose unused reset tokens should be invalidated.
            used_at: Timezone-aware UTC timestamp to record as the invalidation
                time.

        Returns:
            The number of token rows that were invalidated.
        """
        result = self._db.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.user_id == user_id,
                PasswordResetToken.used_at.is_(None),
            )
            .values(used_at=used_at)
        )
        return result.rowcount
