"""Unit tests for AuthService registration, login, and password-reset logic.

The service is tested against in-memory fake repositories and a commit-stub
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
from app.config.settings import Settings
from app.core.exceptions import (
    AccountLockedError,
    EmailAlreadyRegisteredError,
    ExpiredPasswordResetTokenError,
    InactiveAccountError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    UsedPasswordResetTokenError,
)
from app.core.reset_tokens import hash_password_reset_token
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
_NEW_PASSWORD = "N3w-Password!"

_RESET_LIFETIME_MINUTES = 30

_TEST_SETTINGS = Settings(
    jwt_secret_key="test-only-secret-with-at-least-32-characters!",
    password_reset_token_expire_minutes=_RESET_LIFETIME_MINUTES,
)

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
        self.get_by_id_calls: list[uuid.UUID] = []
        self.get_by_id_with_for_update: list[bool] = []
        self.created: list[SimpleNamespace] = []
        self.update_calls: list[dict] = []
        self.update_password_calls: list[dict] = []

    def exists_by_email(self, email: str) -> bool:
        """Return whether a user with the email is stored."""
        self.exists_calls.append(email)
        return email in self.users_by_email

    def get_by_email(self, email: str, *, for_update: bool = False) -> SimpleNamespace | None:
        """Return the stored user for the email, or None."""
        self.get_calls.append(email)
        self.get_with_for_update.append(for_update)
        return self.users_by_email.get(email)

    def get_by_id(self, user_id: uuid.UUID, *, for_update: bool = False) -> SimpleNamespace | None:
        """Return the stored user for the id, or None."""
        self.get_by_id_calls.append(user_id)
        self.get_by_id_with_for_update.append(for_update)
        for user in self.users_by_email.values():
            if user.id == user_id:
                return user
        return None

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

    def update_password(self, user: SimpleNamespace, password_hash: str) -> SimpleNamespace:
        """Replace the stored password hash for a user."""
        self.update_password_calls.append({"user": user, "password_hash": password_hash})
        user.password_hash = password_hash
        return user


class FakePasswordResetTokenRepository:
    """In-memory stand-in for PasswordResetTokenRepository.

    Stores real ``PasswordResetToken`` ORM instances and applies the column
    defaults a database flush/refresh would populate, so the service is
    exercised against genuine model objects without a database.
    """

    def __init__(self) -> None:
        """Initialize the fake with empty in-memory storage."""
        self.records_by_hash: dict[str, object] = {}
        self.created: list[object] = []
        self.get_calls: list[str] = []
        self.get_with_for_update: list[bool] = []
        self.mark_used_calls: list[object] = []
        self.invalidated_user_ids: list[uuid.UUID] = []
        self.invalidated_at: list[datetime] = []

    def create(self, token):
        """Store a reset token, applying model defaults like a real flush."""
        now = datetime.now(UTC)
        token.id = uuid.uuid4()
        token.created_at = now
        token.updated_at = now
        self.records_by_hash[token.token_hash] = token
        self.created.append(token)
        return token

    def get_by_token_hash(self, token_hash: str, *, for_update: bool = False):
        """Return the stored reset token for the digest, or None."""
        self.get_calls.append(token_hash)
        self.get_with_for_update.append(for_update)
        return self.records_by_hash.get(token_hash)

    def mark_used(self, token, used_at: datetime):
        """Record that a reset token is spent."""
        token.used_at = used_at
        self.mark_used_calls.append(token)
        return token

    def invalidate_unused_for_user(self, user_id: uuid.UUID, used_at: datetime) -> int:
        """Spend every still-unused reset token belonging to a user."""
        self.invalidated_user_ids.append(user_id)
        self.invalidated_at.append(used_at)
        invalidated = 0
        for record in self.records_by_hash.values():
            if record.user_id == user_id and record.used_at is None:
                record.used_at = used_at
                invalidated += 1
        return invalidated


class PasswordResetTestCase(unittest.TestCase):
    """Shared fixture for the password-reset service tests."""

    def setUp(self) -> None:
        """Build a fresh service with fake repositories and a stub session."""
        self.repository = FakeUserRepository()
        self.reset_tokens = FakePasswordResetTokenRepository()
        self.db = mock.Mock()
        self.service = AuthService(
            db=self.db,
            repository=self.repository,
            reset_token_repository=self.reset_tokens,
            settings=_TEST_SETTINGS,
        )

    def _register_user(self, **overrides) -> SimpleNamespace:
        """Store a user with the fake repository and return it."""
        user = _make_user(**overrides)
        self.repository.users_by_email[user.email] = user
        return user

    def _issue_token(self, email: str = _EMAIL) -> tuple[str, object]:
        """Issue a reset token and return it with its stored record.

        The stub session is reset afterwards so a test that asserts on commits
        or rollbacks measures only the operation it invokes itself, not the
        issuance performed here.
        """
        raw_token = self.service.create_password_reset_token(email)
        self.assertIsNotNone(raw_token)
        record = self.reset_tokens.records_by_hash[hash_password_reset_token(raw_token)]
        self.db.reset_mock()
        return raw_token, record


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


class PasswordResetTokenCreationTests(PasswordResetTestCase):
    """Issuing password-reset tokens."""

    def test_issued_token_is_non_empty(self) -> None:
        """A created reset token is a non-empty raw string."""
        self._register_user()

        token = self.service.create_password_reset_token(_EMAIL)

        self.assertIsInstance(token, str)
        self.assertTrue(token)

    def test_two_issued_tokens_differ(self) -> None:
        """Two issued reset tokens are never equal."""
        self._register_user()

        first = self.service.create_password_reset_token(_EMAIL)
        second = self.service.create_password_reset_token(_EMAIL)

        self.assertNotEqual(first, second)

    def test_token_is_associated_with_the_requesting_user(self) -> None:
        """The stored record points at the account that requested the token."""
        user = self._register_user()

        _, record = self._issue_token()

        self.assertEqual(record.user_id, user.id)

    def test_only_the_token_hash_is_persisted(self) -> None:
        """The raw token is never stored; only its deterministic digest is."""
        self._register_user()

        raw_token, record = self._issue_token()

        self.assertEqual(record.token_hash, hash_password_reset_token(raw_token))
        self.assertNotEqual(record.token_hash, raw_token)
        for stored in self.reset_tokens.records_by_hash:
            self.assertNotEqual(stored, raw_token)

    def test_token_expires_at_uses_the_configured_lifetime(self) -> None:
        """Expiry is the configured lifetime after issuance."""
        self._register_user()

        before = datetime.now(UTC)
        _, record = self._issue_token()
        after = datetime.now(UTC)
        expected_min = before + timedelta(minutes=_RESET_LIFETIME_MINUTES)
        expected_max = after + timedelta(minutes=_RESET_LIFETIME_MINUTES)

        self.assertGreaterEqual(record.expires_at, expected_min)
        self.assertLessEqual(record.expires_at, expected_max)

    def test_new_token_starts_unused(self) -> None:
        """A freshly issued token has not been consumed."""
        self._register_user()

        _, record = self._issue_token()

        self.assertIsNone(record.used_at)

    def test_new_request_invalidates_previous_unused_token(self) -> None:
        """Issuing a new token spends the previous one, so only the latest link works."""
        self._register_user()
        first_token, first_record = self._issue_token()

        self.service.create_password_reset_token(_EMAIL)

        self.assertIsNotNone(first_record.used_at)
        with self.assertRaises(UsedPasswordResetTokenError):
            self.service.validate_password_reset_token(first_token)

    def test_invalidation_only_touches_the_requesting_user(self) -> None:
        """Invalidation is scoped to one account and leaves others usable."""
        other = _make_user(email="other@example.com")
        self.repository.users_by_email[other.email] = other
        self._register_user()
        other_token, other_record = self._issue_token(email=other.email)
        _, own_record = self._issue_token()

        self.service.create_password_reset_token(_EMAIL)

        own_user = self.repository.users_by_email[_EMAIL]
        self.assertIsNone(other_record.used_at)
        self.assertIsNotNone(own_record.used_at)
        self.assertEqual(self.reset_tokens.invalidated_user_ids[-1], own_user.id)
        self.assertEqual(self.reset_tokens.invalidated_user_ids[-1], own_record.user_id)
        self.assertTrue(other_token)

    def test_unknown_email_returns_none_without_creating_a_token(self) -> None:
        """An unregistered address yields no token.

        The caller can then answer an unknown address identically to a known one
        without leaking account existence.
        """
        self.service.create_password_reset_token("ghost@example.com")

        self.assertEqual(len(self.reset_tokens.created), 0)
        self.assertFalse(self.db.commit.called)

    def test_unknown_email_returns_none(self) -> None:
        """An unregistered address returns None rather than raising."""
        self.assertIsNone(self.service.create_password_reset_token("ghost@example.com"))

    def test_email_is_normalized_before_lookup(self) -> None:
        """The email is normalized through the shared registration/login path."""
        self._register_user()

        self.service.create_password_reset_token("  User@Example.COM  ")

        self.assertIn("user@example.com", self.repository.get_calls)

    def test_token_creation_commits_once(self) -> None:
        """Issuing a token is a single committed transaction."""
        self._register_user()

        self.service.create_password_reset_token(_EMAIL)

        self.assertEqual(self.db.commit.call_count, 1)

    def test_persistence_failure_rolls_back(self) -> None:
        """A failure while storing the token rolls the transaction back."""
        self._register_user()
        self.reset_tokens.create = mock.Mock(side_effect=RuntimeError("db down"))

        with self.assertRaises(RuntimeError):
            self.service.create_password_reset_token(_EMAIL)

        self.assertTrue(self.db.rollback.called)
        self.assertFalse(self.db.commit.called)

    def _record_for(self, raw_token: str):
        """Return the stored record for a raw token."""
        return self.reset_tokens.records_by_hash[hash_password_reset_token(raw_token)]


class PasswordResetTokenValidationTests(PasswordResetTestCase):
    """Validating a submitted password-reset token."""

    def test_valid_token_resolves_to_its_record(self) -> None:
        """A fresh, unexpired token resolves to its stored record."""
        user = self._register_user(email="other@example.com")
        raw_token, record = self._issue_token(email=user.email)

        resolved = self.service.validate_password_reset_token(raw_token)

        self.assertIs(resolved, record)
        self.assertEqual(resolved.user_id, user.id)

    def test_lookup_is_by_hash_not_by_raw_token(self) -> None:
        """The submitted token is hashed and located by its digest."""
        self._register_user()
        raw_token, _ = self._issue_token()

        self.service.validate_password_reset_token(raw_token)

        self.assertEqual(
            self.reset_tokens.get_calls,
            [hash_password_reset_token(raw_token)],
        )

    def test_unknown_token_is_rejected(self) -> None:
        """A token matching no stored digest is rejected."""
        self._register_user()

        with self.assertRaises(InvalidPasswordResetTokenError):
            self.service.validate_password_reset_token("never-issued-token")

    def test_expired_token_is_rejected(self) -> None:
        """A token past its expiry is rejected as expired."""
        self._register_user()
        raw_token, record = self._issue_token()
        record.expires_at = datetime.now(UTC) - timedelta(seconds=1)

        with self.assertRaises(ExpiredPasswordResetTokenError):
            self.service.validate_password_reset_token(raw_token)

    def test_token_expiring_exactly_now_is_rejected(self) -> None:
        """Expiry is inclusive: a token whose expiry has passed is unusable."""
        self._register_user()
        raw_token, record = self._issue_token()
        record.expires_at = datetime.now(UTC) - timedelta(microseconds=1)

        with self.assertRaises(ExpiredPasswordResetTokenError):
            self.service.validate_password_reset_token(raw_token)

    def test_consumed_token_is_rejected(self) -> None:
        """An already-consumed token is rejected as used."""
        self._register_user()
        raw_token, record = self._issue_token()
        record.used_at = datetime.now(UTC)

        with self.assertRaises(UsedPasswordResetTokenError):
            self.service.validate_password_reset_token(raw_token)

    def test_consumed_token_is_rejected_before_expiry(self) -> None:
        """A spent token reports as used even while still within its lifetime."""
        self._register_user()
        raw_token, record = self._issue_token()
        record.used_at = datetime.now(UTC)

        with self.assertRaises(UsedPasswordResetTokenError):
            self.service.validate_password_reset_token(raw_token)

    def test_validation_locks_the_token_row_when_requested(self) -> None:
        """Validation can lock the token row to serialize redemptions."""
        self._register_user()
        raw_token, _ = self._issue_token()

        self.service.validate_password_reset_token(raw_token, for_update=True)

        self.assertEqual(self.reset_tokens.get_with_for_update, [True])

    def test_validation_without_lock_does_not_lock(self) -> None:
        """A read-only validation does not take a row lock."""
        self._register_user()
        raw_token, _ = self._issue_token()

        self.service.validate_password_reset_token(raw_token)

        self.assertEqual(self.reset_tokens.get_with_for_update, [False])


class PasswordResetTests(PasswordResetTestCase):
    """Redeeming a password-reset token."""

    def test_new_password_is_bcrypt_hashed(self) -> None:
        """The replacement password is stored as a bcrypt hash."""
        self._register_user()
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        stored = self.repository.update_password_calls[0]["password_hash"]
        self.assertTrue(stored.startswith("$2b$"))
        self.assertTrue(verify_password(_NEW_PASSWORD, stored))

    def test_plaintext_password_is_never_stored(self) -> None:
        """The plaintext new password appears nowhere in the stored state."""
        self._register_user()
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        stored_hash = self.repository.update_password_calls[0]["password_hash"]
        self.assertNotEqual(stored_hash, _NEW_PASSWORD)
        self.assertNotIn(_NEW_PASSWORD, repr(vars(self.repository.users_by_email[_EMAIL])))

    def test_password_hash_changes(self) -> None:
        """Resetting replaces the stored hash."""
        user = self._register_user()
        original_hash = user.password_hash
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertNotEqual(user.password_hash, original_hash)

    def test_old_password_stops_working_and_new_one_works(self) -> None:
        """After a reset only the new password authenticates the account."""
        user = self._register_user()
        original_hash = user.password_hash
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertFalse(verify_password(_PASSWORD, user.password_hash))
        self.assertTrue(verify_password(_NEW_PASSWORD, user.password_hash))
        self.assertTrue(verify_password(_PASSWORD, original_hash))

    def test_failed_login_attempts_are_cleared(self) -> None:
        """A successful reset clears the consecutive failure counter."""
        user = self._register_user(failed_login_attempts=MAX_FAILED_LOGIN_ATTEMPTS)
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertEqual(user.failed_login_attempts, 0)

    def test_locked_until_is_cleared(self) -> None:
        """A successful reset clears an active lockout."""
        user = self._register_user(locked_until=datetime.now(UTC) + timedelta(minutes=10))
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertIsNone(user.locked_until)

    def test_last_login_at_is_not_updated(self) -> None:
        """A reset is not a login, so the login timestamp is left untouched."""
        self._register_user()
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertIsNone(self.repository.users_by_email[_EMAIL].last_login_at)
        self.assertEqual(self.repository.update_calls[-1]["last_login_at"], _UNSET)

    def test_reset_token_is_consumed(self) -> None:
        """The redeemed token is marked used at the time of the reset."""
        self._register_user()
        before = datetime.now(UTC)
        raw_token, record = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertIsNotNone(record.used_at)
        self.assertGreaterEqual(record.used_at, before)

    def test_reset_token_cannot_be_reused(self) -> None:
        """A consumed token cannot be redeemed a second time."""
        self._register_user()
        raw_token, _ = self._issue_token()
        self.service.reset_password(raw_token, _NEW_PASSWORD)

        with self.assertRaises(UsedPasswordResetTokenError):
            self.service.reset_password(raw_token, "Another-Password1!")

    def test_user_is_taken_from_the_stored_record_only(self) -> None:
        """The account reset is determined by the token record, not the caller.

        The service accepts no user identifier, so a token can only ever affect
        the account it was issued for.
        """
        first = self._register_user()
        second = _make_user(email="second@example.com")
        self.repository.users_by_email[second.email] = second
        second_hash_before = second.password_hash
        raw_token, record = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertEqual(self.repository.get_by_id_calls, [record.user_id])
        self.assertEqual(self.repository.get_by_id_calls, [first.id])
        self.assertEqual(second.password_hash, second_hash_before)
        self.assertTrue(verify_password(_NEW_PASSWORD, first.password_hash))

    def test_reset_commits_exactly_once(self) -> None:
        """Password update, token consumption, and lockout clearing commit together."""
        self._register_user(failed_login_attempts=2)
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertEqual(self.db.commit.call_count, 1)
        self.assertFalse(self.db.rollback.called)

    def test_reset_does_not_issue_authentication_tokens(self) -> None:
        """No access or refresh token is created; the user logs in afterwards."""
        self._register_user()
        raw_token, _ = self._issue_token()

        with (
            mock.patch("app.core.tokens.create_access_token") as access,
            mock.patch("app.core.tokens.create_refresh_token") as refresh,
        ):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertFalse(access.called)
        self.assertFalse(refresh.called)

    def test_reset_does_not_touch_email_verification(self) -> None:
        """Verification state is orthogonal to password reset."""
        self._register_user(email_verified_at=None)
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertIsNone(self.repository.users_by_email[_EMAIL].email_verified_at)
        self.assertEqual(self.repository.update_calls[-1]["email_verified_at"], _UNSET)

    def test_reset_does_not_change_is_active(self) -> None:
        """Resetting a password does not activate or deactivate an account."""
        self._register_user()
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertEqual(self.repository.update_calls[-1]["is_active"], _UNSET)
        self.assertTrue(self.repository.users_by_email[_EMAIL].is_active)


class PasswordResetAtomicityTests(PasswordResetTestCase):
    """Failure handling and rollback for the reset transaction."""

    def test_failed_password_update_does_not_consume_the_token(self) -> None:
        """If the password write fails, the token is never marked used."""
        self._register_user()
        raw_token, record = self._issue_token()
        self.repository.update_password = mock.Mock(side_effect=RuntimeError("write failed"))

        with self.assertRaises(RuntimeError):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertIsNone(record.used_at)
        self.assertEqual(self.reset_tokens.mark_used_calls, [])

    def test_failed_password_update_rolls_back(self) -> None:
        """A failed password write rolls the transaction back."""
        self._register_user()
        raw_token, _ = self._issue_token()
        self.repository.update_password = mock.Mock(side_effect=RuntimeError("write failed"))

        with self.assertRaises(RuntimeError):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertTrue(self.db.rollback.called)
        self.assertFalse(self.db.commit.called)

    def test_failed_token_consumption_rolls_back_the_password_change(self) -> None:
        """If the token cannot be marked used, the whole transaction rolls back.

        Discarding the already-flushed password write is the database
        guarantee behind ``rollback``; the in-memory fakes cannot emulate it,
        so this asserts that the rollback is requested and that nothing is
        committed.
        """
        self._register_user()
        raw_token, _ = self._issue_token()
        self.reset_tokens.mark_used = mock.Mock(side_effect=RuntimeError("write failed"))

        with self.assertRaises(RuntimeError):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertTrue(self.db.rollback.called)
        self.assertFalse(self.db.commit.called)

    def test_unknown_token_rolls_back(self) -> None:
        """A token that matches no stored digest still rolls the transaction back.

        Token resolution happens inside the transactional block, so an
        unrecognized token cannot escape without releasing the transaction.
        """
        self._register_user()

        with self.assertRaises(InvalidPasswordResetTokenError):
            self.service.reset_password("never-issued-token", _NEW_PASSWORD)

        self.assertTrue(self.db.rollback.called)
        self.assertFalse(self.db.commit.called)
        self.assertEqual(self.repository.get_by_id_calls, [])

    def test_used_token_rolls_back(self) -> None:
        """Re-presenting a consumed token rolls the transaction back.

        The failed lookup takes a ``SELECT ... FOR UPDATE`` row lock before the
        consumed check fails, so this path must roll back rather than leave that
        lock held until the session closes.
        """
        self._register_user()
        raw_token, record = self._issue_token()
        record.used_at = datetime.now(UTC)

        with self.assertRaises(UsedPasswordResetTokenError):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertTrue(self.db.rollback.called)
        self.assertFalse(self.db.commit.called)
        self.assertEqual(self.reset_tokens.get_with_for_update, [True])
        self.assertEqual(self.repository.get_by_id_calls, [])

    def test_expired_token_rolls_back(self) -> None:
        """An expired token rolls the transaction back like any other rejection."""
        self._register_user()
        raw_token, record = self._issue_token()
        record.expires_at = datetime.now(UTC) - timedelta(minutes=1)

        with self.assertRaises(ExpiredPasswordResetTokenError):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertTrue(self.db.rollback.called)
        self.assertFalse(self.db.commit.called)
        self.assertEqual(self.repository.get_by_id_calls, [])

    def test_token_lookup_failure_rolls_back_and_reraises(self) -> None:
        """A repository failure during lookup rolls back and re-raises unchanged."""
        self._register_user()
        raw_token, _ = self._issue_token()
        self.reset_tokens.get_by_token_hash = mock.Mock(side_effect=RuntimeError("lookup failed"))

        with self.assertRaises(RuntimeError) as caught:
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertEqual(str(caught.exception), "lookup failed")
        self.assertTrue(self.db.rollback.called)
        self.assertFalse(self.db.commit.called)

    def test_password_hashing_failure_rolls_back(self) -> None:
        """A failure while hashing the new password rolls the transaction back."""
        self._register_user()
        raw_token, record = self._issue_token()

        with (
            mock.patch("app.modules.auth.service.hash_password", side_effect=ValueError("bad")),
            self.assertRaises(ValueError) as caught,
        ):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertEqual(str(caught.exception), "bad")
        self.assertTrue(self.db.rollback.called)
        self.assertFalse(self.db.commit.called)
        self.assertIsNone(record.used_at)
        self.assertEqual(self.repository.update_password_calls, [])

    def test_hashing_failure_never_locks_the_user_row(self) -> None:
        """The user row is locked only after hashing succeeds.

        bcrypt must never run while the user lock is held, so a hashing failure
        must leave no user lock outstanding.
        """
        self._register_user()
        raw_token, _ = self._issue_token()

        with (
            mock.patch("app.modules.auth.service.hash_password", side_effect=ValueError("bad")),
            self.assertRaises(ValueError),
        ):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertEqual(self.repository.get_by_id_calls, [])
        self.assertEqual(self.repository.get_by_id_with_for_update, [])

    def test_hashing_runs_after_the_token_lock_and_before_the_user_lock(self) -> None:
        """Order is token row lock, then hashing, then the user row lock."""
        self._register_user()
        raw_token, _ = self._issue_token()
        order: list[str] = []

        def _record_token_lookup(*_args, **_kwargs):
            order.append("token-lock")
            return self.reset_tokens.records_by_hash[hash_password_reset_token(raw_token)]

        def _record_hash(*_args, **_kwargs):
            order.append("hash")
            return "$2b$12$" + "x" * 53

        def _record_user_lookup(*_args, **_kwargs):
            order.append("user-lock")
            return self.repository.users_by_email[_EMAIL]

        self.reset_tokens.get_by_token_hash = mock.Mock(side_effect=_record_token_lookup)

        with (
            mock.patch("app.modules.auth.service.hash_password", side_effect=_record_hash),
            mock.patch.object(self.repository, "get_by_id", side_effect=_record_user_lookup),
        ):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertEqual(order, ["token-lock", "hash", "user-lock"])

    def test_rejected_password_leaves_the_token_usable(self) -> None:
        """A password bcrypt rejects is a caller error that spends no token."""
        self._register_user()
        original_hash = self.repository.users_by_email[_EMAIL].password_hash
        raw_token, record = self._issue_token()

        with self.assertRaises(ValueError):
            self.service.reset_password(raw_token, "x" * 73)

        self.assertIsNone(record.used_at)
        self.assertEqual(self.repository.users_by_email[_EMAIL].password_hash, original_hash)
        self.assertTrue(self.db.rollback.called)

    def test_empty_password_leaves_the_token_usable(self) -> None:
        """An empty new password is rejected without consuming the token."""
        self._register_user()
        raw_token, record = self._issue_token()

        with self.assertRaises(ValueError):
            self.service.reset_password(raw_token, "")

        self.assertIsNone(record.used_at)
        self.assertTrue(self.db.rollback.called)

    def test_deleted_user_cannot_reset(self) -> None:
        """A token whose user no longer exists is rejected as invalid."""
        self._register_user()
        raw_token, record = self._issue_token()
        del self.repository.users_by_email[_EMAIL]

        with self.assertRaises(InvalidPasswordResetTokenError):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertIsNone(record.used_at)
        self.assertTrue(self.db.rollback.called)

    def test_deactivated_user_cannot_reset(self) -> None:
        """A token belonging to a deactivated account is rejected as invalid."""
        self._register_user(is_active=False)
        raw_token, record = self._issue_token()

        with self.assertRaises(InvalidPasswordResetTokenError):
            self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertIsNone(record.used_at)
        self.assertTrue(self.db.rollback.called)


class PasswordResetConcurrencyTests(PasswordResetTestCase):
    """Row locking and single-use enforcement for concurrent redemptions.

    Actual serialization is a database guarantee provided by
    ``SELECT ... FOR UPDATE``; these tests assert that the service requests that
    lock and that the resulting state transitions make a second redemption of the
    same token impossible.
    """

    def test_reset_locks_the_token_row(self) -> None:
        """The token row is locked so concurrent redemptions serialize."""
        self._register_user()
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertEqual(self.reset_tokens.get_with_for_update, [True])

    def test_reset_locks_the_user_row(self) -> None:
        """The user row is locked before the password write.

        The password update and the lockout clearing therefore serialize against
        concurrent logins, matching the existing login concurrency pattern.
        """
        self._register_user()
        raw_token, _ = self._issue_token()

        self.service.reset_password(raw_token, _NEW_PASSWORD)

        self.assertEqual(self.repository.get_by_id_with_for_update, [True])

    def test_same_token_cannot_produce_two_successful_resets(self) -> None:
        """Two redemptions of one token yield exactly one password change."""
        self._register_user()
        raw_token, _ = self._issue_token()
        self.service.reset_password(raw_token, _NEW_PASSWORD)
        hash_after_first = self.repository.users_by_email[_EMAIL].password_hash

        with self.assertRaises(UsedPasswordResetTokenError):
            self.service.reset_password(raw_token, "Concurrent-Password1!")

        current_hash = self.repository.users_by_email[_EMAIL].password_hash
        self.assertEqual(current_hash, hash_after_first)
        self.assertTrue(verify_password(_NEW_PASSWORD, current_hash))

    def test_a_newer_token_supersedes_an_in_flight_one(self) -> None:
        """Once a second token is issued, the first can no longer be redeemed."""
        self._register_user()
        first_token, first_record = self._issue_token()
        second_token, second_record = self._issue_token()

        with self.assertRaises(UsedPasswordResetTokenError):
            self.service.reset_password(first_token, _NEW_PASSWORD)

        self.assertIsNotNone(first_record.used_at)
        self.assertIsNone(second_record.used_at)
        self.service.reset_password(second_token, _NEW_PASSWORD)
        self.assertTrue(
            verify_password(_NEW_PASSWORD, self.repository.users_by_email[_EMAIL].password_hash)
        )

    def test_each_token_is_single_use_independently(self) -> None:
        """Consuming one token never consumes a different, still-valid token."""
        self._register_user()
        first_token, first_record = self._issue_token()
        # A second user owns a second token, so neither supersedes the other.
        other = _make_user(email="other@example.com")
        self.repository.users_by_email[other.email] = other
        other_token, other_record = self._issue_token(email=other.email)

        self.service.reset_password(first_token, _NEW_PASSWORD)

        self.assertIsNotNone(first_record.used_at)
        self.assertIsNone(other_record.used_at)
        self.service.reset_password(other_token, "Other-Password1!")


class NormalizationTests(unittest.TestCase):
    """The single email normalization path shared by registration and login."""

    def test_normalize_email_strips_and_lowercases(self):
        """Whitespace is removed and the address is lowercased."""
        self.assertEqual(AuthService._normalize_email(" User@Example.COM "), "user@example.com")
        self.assertEqual(AuthService._normalize_email("USER@EXAMPLE.COM"), "user@example.com")
        self.assertEqual(AuthService._normalize_email("  user@example.com  "), "user@example.com")


if __name__ == "__main__":
    unittest.main()
