"""Unit tests for AuthService registration and login business logic.

The service is tested against an in-memory FakeUserRepository and a commit-stub
session. No real PostgreSQL database (production or otherwise) is touched.

Repository integration tests against a test database should be added later,
once test-database infrastructure exists, to cover SQLAlchemy flush/refresh
behaviour and the real update_authentication_state path.
"""

# ruff: noqa: E402

import sys
import unittest
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sqlalchemy.exc import IntegrityError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app.models  # noqa: F401  (registers all ORM models on Base.metadata)
from app.core.exceptions import (
    AccountLockedError,
    EmailAlreadyRegisteredError,
    InactiveAccountError,
    InvalidCredentialsError,
)
from app.core.security import hash_password, verify_password
from app.modules.auth.schemas import UserLoginRequest, UserRegistrationRequest
from app.modules.auth.service import (
    EMAIL_UNIQUE_CONSTRAINT_NAME,
    LOCKOUT_DURATION_MINUTES,
    MAX_FAILED_LOGIN_ATTEMPTS,
    AuthService,
)

_EMAIL = "user@example.com"
_PASSWORD = "Password123!"

_UNSET = object()


class _FakeDiag:
    """Stand-in for psycopg's diagnostic with a constraint name."""

    def __init__(self, constraint_name: str) -> None:
        """Store the constraint name reported by the database."""
        self.constraint_name = constraint_name


class _FakeOrig:
    """Stand-in for the DBAPI origin attached to an IntegrityError."""

    def __init__(self, constraint_name: str) -> None:
        """Store a diagnostic carrying the constraint name."""
        self.diag = _FakeDiag(constraint_name)


class _FakeMessageOrig:
    """Stand-in DBAPI origin that identifies the constraint by message only."""

    def __str__(self) -> str:
        return 'duplicate key value violates unique constraint "uq_users_email"'


def _make_user(*, email=_EMAIL, password=_PASSWORD, **overrides):
    """Build a fake user with sensible defaults for service tests."""
    user = SimpleNamespace(
        id=uuid.uuid4(),
        full_name="Test User",
        email=email,
        password_hash=hash_password(password),
        profile_photo_url=None,
        currency="USD",
        timezone="UTC",
        onboarding_completed=False,
        is_active=True,
        email_verified_at=None,
        last_login_at=None,
        failed_login_attempts=0,
        locked_until=None,
        created_at=datetime.now(UTC),
    )
    for key, value in overrides.items():
        setattr(user, key, value)
    return user


class FakeUserRepository:
    """In-memory stand-in for UserRepository used to isolate service tests.

    Mirrors the repository surface the service uses and applies the User model
    defaults that the real repository's flush/refresh would populate.
    """

    def __init__(self) -> None:
        """Initialize the fake with empty in-memory storage."""
        self.users_by_email: dict[str, SimpleNamespace] = {}
        self.exists_calls: list[str] = []
        self.get_calls: list[str] = []
        self.get_with_for_update: list[bool] = []
        self.created: list[SimpleNamespace] = []
        self.update_calls: list[dict] = []

    def exists_by_email(self, email: str) -> bool:
        """Return whether a user with the email is stored."""
        self.exists_calls.append(email)
        return email in self.users_by_email

    def get_by_email(self, email: str, *, for_update: bool = False) -> SimpleNamespace | None:
        """Return the stored user for the email, or None."""
        self.get_calls.append(email)
        self.get_with_for_update.append(for_update)
        return self.users_by_email.get(email)

    def create(self, user: SimpleNamespace) -> SimpleNamespace:
        """Store a user, applying model defaults like a real flush/refresh."""
        defaults = {
            "id": uuid.uuid4(),
            "profile_photo_url": None,
            "currency": "USD",
            "timezone": "UTC",
            "onboarding_completed": False,
            "is_active": True,
            "email_verified_at": None,
            "last_login_at": None,
            "failed_login_attempts": 0,
            "locked_until": None,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
        for key, value in defaults.items():
            if getattr(user, key, None) is None:
                setattr(user, key, value)
        self.users_by_email[user.email] = user
        self.created.append(user)
        return user

    def update_authentication_state(
        self,
        user: SimpleNamespace,
        *,
        last_login_at: object = _UNSET,
        failed_login_attempts: object = _UNSET,
        locked_until: object = _UNSET,
        email_verified_at: object = _UNSET,
        is_active: object = _UNSET,
    ) -> SimpleNamespace:
        """Apply authentication state updates to a stored user."""
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
        self.update_calls.append(
            {
                "user": user,
                "last_login_at": last_login_at,
                "failed_login_attempts": failed_login_attempts,
                "locked_until": locked_until,
                "email_verified_at": email_verified_at,
                "is_active": is_active,
            }
        )
        return user


class RegistrationTests(unittest.TestCase):
    """Registration business logic."""

    def setUp(self) -> None:
        """Build a fresh service with a fake repository and stub session."""
        self.repository = FakeUserRepository()
        self.db = mock.Mock()
        self.service = AuthService(db=self.db, repository=self.repository)

    def _request(self, *, email=_EMAIL, password=_PASSWORD, full_name="Test User"):
        return UserRegistrationRequest(full_name=full_name, email=email, password=password)

    def test_successful_registration_returns_safe_profile(self):
        """Registering a new user returns a safe profile and persists."""
        result = self.service.register(self._request())

        self.assertEqual(len(self.repository.created), 1)
        created = self.repository.created[0]
        self.assertEqual(result.id, created.id)
        self.assertEqual(result.email, _EMAIL)
        self.assertEqual(result.full_name, "Test User")
        self.assertTrue(self.db.commit.called)
        self.assertNotIn("password_hash", result.model_dump())
        self.assertNotIn("failed_login_attempts", result.model_dump())
        self.assertNotIn("locked_until", result.model_dump())

    def test_registration_normalizes_email(self):
        """Whitespace and case are stripped before duplicate checks and storage."""
        self.service.register(self._request(email="  User@Example.COM  "))

        self.assertIn("user@example.com", self.repository.exists_calls)
        self.assertEqual(self.repository.created[0].email, "user@example.com")

    def test_duplicate_email_is_rejected(self):
        """Registering an existing email raises a domain exception."""
        self.repository.users_by_email[_EMAIL] = _make_user(email=_EMAIL)

        with self.assertRaises(EmailAlreadyRegisteredError):
            self.service.register(self._request())

        self.assertEqual(len(self.repository.created), 0)

    def test_duplicate_registration_race_is_converted(self):
        """A concurrent duplicate insert is converted to the domain error."""
        self.repository.create = mock.Mock(
            side_effect=IntegrityError("INSERT", {}, _FakeOrig(EMAIL_UNIQUE_CONSTRAINT_NAME))
        )

        with self.assertRaises(EmailAlreadyRegisteredError):
            self.service.register(self._request())

        self.assertTrue(self.db.rollback.called)

    def test_unrelated_integrity_error_is_not_converted(self):
        """A non-duplicate integrity error is re-raised after rollback."""
        self.repository.create = mock.Mock(
            side_effect=IntegrityError("INSERT", {}, _FakeOrig("uq_another_table_col"))
        )

        with self.assertRaises(IntegrityError):
            self.service.register(self._request())

        self.assertTrue(self.db.rollback.called)

    def test_duplicate_race_recognized_via_message_fallback(self):
        """The duplicate conversion also works from the driver message alone."""
        self.repository.create = mock.Mock(
            side_effect=IntegrityError("INSERT", {}, _FakeMessageOrig())
        )

        with self.assertRaises(EmailAlreadyRegisteredError):
            self.service.register(self._request())

    def test_password_is_hashed_not_stored_plaintext(self):
        """The stored password is a bcrypt hash, never the plaintext."""
        self.service.register(self._request(password="s3cr3t!"))

        stored_hash = self.repository.created[0].password_hash
        self.assertNotEqual(stored_hash, "s3cr3t!")
        self.assertTrue(stored_hash.startswith("$2b$"))
        self.assertTrue(verify_password("s3cr3t!", stored_hash))


class LoginTests(unittest.TestCase):
    """Credential authentication business logic."""

    def setUp(self) -> None:
        """Build a fresh service with a fake repository and stub session."""
        self.repository = FakeUserRepository()
        self.db = mock.Mock()
        self.service = AuthService(db=self.db, repository=self.repository)

    def _login(self, *, email=_EMAIL, password=_PASSWORD):
        return self.service.login(UserLoginRequest(email=email, password=password))

    def _register_user(self, **overrides):
        user = _make_user(**overrides)
        self.repository.users_by_email[user.email] = user
        return user

    def test_successful_login_returns_safe_profile(self):
        """A valid email/password combination authenticates the user."""
        user = self._register_user()

        result = self._login()

        self.assertEqual(result.id, user.id)
        self.assertEqual(result.email, user.email)
        self.assertTrue(self.db.commit.called)
        self.assertNotIn("password_hash", result.model_dump())
        self.assertNotIn("failed_login_attempts", result.model_dump())
        self.assertNotIn("locked_until", result.model_dump())

    def test_login_normalizes_email(self):
        """Login looks up the user with the normalized email."""
        self._register_user()

        self._login(email="  User@Example.COM  ")

        self.assertIn("user@example.com", self.repository.get_calls)

    def test_login_requests_row_lock(self):
        """Login locks the user row to serialize authentication-state updates."""
        self._register_user()

        self._login()

        self.assertEqual(self.repository.get_with_for_update, [True])

    def test_wrong_password_raises_generic_failure(self):
        """An incorrect password raises the generic credential failure."""
        self._register_user()

        with self.assertRaises(InvalidCredentialsError):
            self._login(password="wrong-password")

    def test_nonexistent_user_raises_same_failure_as_wrong_password(self):
        """A missing user is indistinguishable from a wrong password."""
        self._register_user()

        with self.assertRaises(InvalidCredentialsError):
            self._login(password="wrong-password")
        with self.assertRaises(InvalidCredentialsError):
            self._login(email="ghost@example.com")

    def test_failed_login_increments_failed_login_attempts(self):
        """A wrong password increments the consecutive failure counter."""
        user = self._register_user(failed_login_attempts=2)

        with self.assertRaises(InvalidCredentialsError):
            self._login(password="wrong-password")

        self.assertEqual(user.failed_login_attempts, 3)
        self.assertIsNone(user.locked_until)

    def test_fifth_failed_attempt_locks_account_for_15_minutes(self):
        """Reaching the maximum failures locks the account for 15 minutes."""
        user = self._register_user(failed_login_attempts=MAX_FAILED_LOGIN_ATTEMPTS - 1)

        before = datetime.now(UTC)
        with self.assertRaises(InvalidCredentialsError):
            self._login(password="wrong-password")
        after = datetime.now(UTC)

        self.assertEqual(user.failed_login_attempts, MAX_FAILED_LOGIN_ATTEMPTS)
        self.assertIsNotNone(user.locked_until)
        self.assertGreaterEqual(
            user.locked_until, before + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        )
        self.assertLessEqual(user.locked_until, after + timedelta(minutes=LOCKOUT_DURATION_MINUTES))

    def test_locked_account_cannot_authenticate(self):
        """A locked account is rejected before the password is verified."""
        self._register_user(locked_until=datetime.now(UTC) + timedelta(minutes=10))

        with self.assertRaises(AccountLockedError):
            self._login()

        self.assertEqual(len(self.repository.update_calls), 0)

    def test_inactive_account_cannot_authenticate(self):
        """A deactivated account is rejected before the password is verified."""
        self._register_user(is_active=False)

        with self.assertRaises(InactiveAccountError):
            self._login()

        self.assertEqual(len(self.repository.update_calls), 0)

    def test_successful_login_resets_failed_login_attempts(self):
        """A successful login resets the consecutive failure counter."""
        user = self._register_user(failed_login_attempts=3)

        self._login()

        self.assertEqual(user.failed_login_attempts, 0)

    def test_successful_login_clears_locked_until(self):
        """A successful login clears an expired lock."""
        user = self._register_user(
            failed_login_attempts=MAX_FAILED_LOGIN_ATTEMPTS,
            locked_until=datetime.now(UTC) - timedelta(minutes=1),
        )

        self._login()

        self.assertIsNone(user.locked_until)

    def test_successful_login_updates_last_login_at(self):
        """A successful login records the login time."""
        self._register_user()

        before = datetime.now(UTC)
        self._login()
        after = datetime.now(UTC)

        last_update = self.repository.update_calls[-1]
        self.assertIsNotNone(last_update["last_login_at"])
        self.assertGreaterEqual(last_update["last_login_at"], before)
        self.assertLessEqual(last_update["last_login_at"], after)


class NormalizationTests(unittest.TestCase):
    """The single email normalization path shared by registration and login."""

    def test_normalize_email_strips_and_lowercases(self):
        """Whitespace is removed and the address is lowercased."""
        self.assertEqual(AuthService._normalize_email(" User@Example.COM "), "user@example.com")
        self.assertEqual(AuthService._normalize_email("USER@EXAMPLE.COM"), "user@example.com")
        self.assertEqual(AuthService._normalize_email("  user@example.com  "), "user@example.com")


if __name__ == "__main__":
    unittest.main()
