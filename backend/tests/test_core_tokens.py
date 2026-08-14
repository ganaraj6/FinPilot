"""Unit tests for the JWT token management component.

All tokens are exercised with a test-only signing secret and a TokenService
built from a Settings instance; the real application settings and the real .env
are never used. No database or network access occurs.
"""

# ruff: noqa: E402

import os
import sys
import unittest
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from pydantic import ValidationError

os.environ["JWT_SECRET_KEY"] = "test-only-secret-with-at-least-32-characters!"
os.environ["JWT_ALGORITHM"] = "HS256"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config.settings import Settings
from app.core.exceptions import (
    ExpiredTokenError,
    InvalidTokenError,
    InvalidTokenTypeError,
)
from app.core.tokens import (
    TokenClaims,
    TokenService,
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_access_token,
    validate_refresh_token,
)

TEST_SECRET = "test-only-secret-with-at-least-32-characters!"
OTHER_SECRET = "a-different-test-only-secret-with-32-characters!"
HS512_TEST_SECRET = "test-only-hs512-secret-key-that-is-at-least-sixty-four-bytes-long"
_USER_ID = uuid.uuid4()


def _make_service(*, secret: str = TEST_SECRET, **settings_overrides) -> TokenService:
    """Build a TokenService with a test-only secret and sensible defaults."""
    return TokenService(Settings(jwt_secret_key=secret, **settings_overrides))


def _signed_payload() -> dict:
    """Return a valid access-token payload for the test user."""
    now = datetime.now(UTC)
    return {
        "sub": str(_USER_ID),
        "token_type": TokenType.ACCESS.value,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }


def _sign(payload: dict) -> str:
    """Sign the given claims with the test-only secret."""
    return jwt.encode(payload, TEST_SECRET, algorithm="HS256")


def _decode_raw(token: str) -> dict:
    """Decode the token payload directly with PyJWT for inspection."""
    return jwt.decode(token, TEST_SECRET, algorithms=["HS256"])


class AccessTokenTests(unittest.TestCase):
    """Access token creation."""

    def setUp(self) -> None:
        """Create a service and a fresh access token per test."""
        self.service = _make_service()
        self.token = self.service.create_access_token(_USER_ID)

    def test_access_token_can_be_created(self) -> None:
        """create_access_token returns a non-empty, three-part JWT."""
        self.assertIsInstance(self.token, str)
        self.assertEqual(len(self.token.split(".")), 3)

    def test_access_token_contains_required_claims(self) -> None:
        """The payload includes sub, exp, iat, jti, and token_type."""
        payload = _decode_raw(self.token)
        for claim in ("sub", "exp", "iat", "jti", "token_type"):
            self.assertIn(claim, payload)

    def test_access_token_subject_is_user_uuid(self) -> None:
        """The sub claim is the string form of the user UUID."""
        self.assertEqual(_decode_raw(self.token)["sub"], str(_USER_ID))

    def test_access_token_has_access_type(self) -> None:
        """The token_type claim is 'access'."""
        self.assertEqual(_decode_raw(self.token)["token_type"], TokenType.ACCESS.value)

    def test_access_token_has_unique_jti(self) -> None:
        """Two access tokens carry different jti values."""
        other = self.service.create_access_token(_USER_ID)
        self.assertNotEqual(
            _decode_raw(self.token)["jti"],
            _decode_raw(other)["jti"],
        )


class RefreshTokenTests(unittest.TestCase):
    """Refresh token creation."""

    def setUp(self) -> None:
        """Create a service and a fresh refresh token per test."""
        self.service = _make_service()
        self.token = self.service.create_refresh_token(_USER_ID)

    def test_refresh_token_can_be_created(self) -> None:
        """create_refresh_token returns a non-empty, three-part JWT."""
        self.assertIsInstance(self.token, str)
        self.assertEqual(len(self.token.split(".")), 3)

    def test_refresh_token_contains_required_claims(self) -> None:
        """The payload includes sub, exp, iat, jti, and token_type."""
        payload = _decode_raw(self.token)
        for claim in ("sub", "exp", "iat", "jti", "token_type"):
            self.assertIn(claim, payload)

    def test_refresh_token_has_refresh_type(self) -> None:
        """The token_type claim is 'refresh'."""
        self.assertEqual(_decode_raw(self.token)["token_type"], TokenType.REFRESH.value)

    def test_refresh_token_expires_later_than_access_token(self) -> None:
        """A refresh token lives substantially longer than an access token."""
        access = self.service.validate_access_token(self.service.create_access_token(_USER_ID))
        refresh = self.service.validate_refresh_token(self.token)
        access_lifetime = access.expires_at - access.issued_at
        refresh_lifetime = refresh.expires_at - refresh.issued_at
        self.assertGreater(refresh_lifetime, access_lifetime)


class ValidationTests(unittest.TestCase):
    """Token decoding and validation behavior."""

    def setUp(self) -> None:
        """Create a service and valid access/refresh tokens per test."""
        self.service = _make_service()
        self.access_token = self.service.create_access_token(_USER_ID)
        self.refresh_token = self.service.create_refresh_token(_USER_ID)

    def test_valid_access_token_validates(self) -> None:
        """A valid access token yields typed claims for the right user."""
        claims = self.service.validate_access_token(self.access_token)
        self.assertIsInstance(claims, TokenClaims)
        self.assertEqual(claims.user_id, _USER_ID)
        self.assertEqual(claims.token_type, TokenType.ACCESS)
        self.assertEqual(claims.issued_at.utcoffset(), timedelta(0))
        self.assertEqual(claims.expires_at.utcoffset(), timedelta(0))

    def test_valid_refresh_token_validates(self) -> None:
        """A valid refresh token yields typed claims for the right user."""
        claims = self.service.validate_refresh_token(self.refresh_token)
        self.assertEqual(claims.user_id, _USER_ID)
        self.assertEqual(claims.token_type, TokenType.REFRESH)

    def test_valid_iat_is_accepted(self) -> None:
        """A token with a valid issued-at time validates successfully."""
        claims = self.service.validate_access_token(self.access_token)
        self.assertLessEqual(claims.issued_at, datetime.now(UTC))

    def test_future_iat_is_rejected(self) -> None:
        """A token issued in the future is rejected."""
        payload = _signed_payload()
        payload["iat"] = datetime.now(UTC) + timedelta(minutes=5)
        with self.assertRaises(InvalidTokenError):
            self.service.validate_access_token(_sign(payload))

    def test_invalid_iat_is_rejected(self) -> None:
        """A non-numeric iat claim is rejected."""
        payload = _signed_payload()
        payload["iat"] = "not-a-timestamp"
        with self.assertRaises(InvalidTokenError):
            self.service.validate_access_token(_sign(payload))

    def test_expired_token_is_rejected(self) -> None:
        """An expired token raises ExpiredTokenError."""
        now = datetime.now(UTC)
        payload = _signed_payload()
        payload["iat"] = now - timedelta(minutes=5)
        payload["exp"] = now - timedelta(minutes=1)
        with self.assertRaises(ExpiredTokenError):
            self.service.validate_access_token(_sign(payload))

    def test_tampered_token_is_rejected(self) -> None:
        """A token with a modified signature is rejected."""
        replacement = "B" if self.access_token[-1] != "B" else "A"
        tampered = self.access_token[:-1] + replacement
        with self.assertRaises(InvalidTokenError):
            self.service.validate_access_token(tampered)

    def test_malformed_token_is_rejected(self) -> None:
        """A non-JWT string is rejected."""
        with self.assertRaises(InvalidTokenError):
            self.service.validate_access_token("not-a-jwt-token")

    def test_missing_subject_is_rejected(self) -> None:
        """A token without a sub claim is rejected."""
        payload = _signed_payload()
        del payload["sub"]
        with self.assertRaises(InvalidTokenError):
            self.service.validate_access_token(_sign(payload))

    def test_invalid_uuid_subject_is_rejected(self) -> None:
        """A sub claim that is not a valid UUID is rejected."""
        payload = _signed_payload()
        payload["sub"] = "not-a-uuid"
        with self.assertRaises(InvalidTokenError):
            self.service.validate_access_token(_sign(payload))

    def test_missing_token_type_is_rejected(self) -> None:
        """A token without a token_type claim is rejected."""
        payload = _signed_payload()
        del payload["token_type"]
        with self.assertRaises(InvalidTokenError):
            self.service.validate_access_token(_sign(payload))

    def test_access_token_rejected_where_refresh_required(self) -> None:
        """An access token fails refresh-token validation."""
        with self.assertRaises(InvalidTokenTypeError):
            self.service.validate_refresh_token(self.access_token)

    def test_refresh_token_rejected_where_access_required(self) -> None:
        """A refresh token fails access-token validation."""
        with self.assertRaises(InvalidTokenTypeError):
            self.service.validate_access_token(self.refresh_token)

    def test_unsupported_algorithm_is_rejected(self) -> None:
        """A token signed with a different algorithm is rejected."""
        token = jwt.encode(_signed_payload(), HS512_TEST_SECRET, algorithm="HS512")
        with self.assertRaises(InvalidTokenError):
            self.service.validate_access_token(token)

    def test_unsigned_token_is_rejected(self) -> None:
        """A token with the 'none' algorithm is rejected."""
        token = jwt.encode(_signed_payload(), key=None, algorithm="none")
        with self.assertRaises(InvalidTokenError):
            self.service.validate_access_token(token)

    def test_token_is_rejected_with_wrong_secret(self) -> None:
        """A token cannot be validated with a different signing secret."""
        other_service = _make_service(secret=OTHER_SECRET)
        with self.assertRaises(InvalidTokenError):
            other_service.validate_access_token(self.access_token)

    def test_every_token_has_a_unique_jti(self) -> None:
        """All generated tokens carry distinct jti values."""
        jtis = {_decode_raw(self.service.create_access_token(_USER_ID))["jti"] for _ in range(10)}
        jtis.add(_decode_raw(self.refresh_token)["jti"])
        self.assertEqual(len(jtis), 11)


class SettingsValidationTests(unittest.TestCase):
    """Lifetime configuration validation in Settings."""

    def test_default_lifetimes_are_valid(self) -> None:
        """The default access/refresh lifetimes pass validation."""
        settings = Settings(jwt_secret_key=TEST_SECRET)
        self.assertEqual(settings.access_token_expire_minutes, 15)
        self.assertEqual(settings.refresh_token_expire_minutes, 60 * 24 * 14)

    def test_access_token_lifetime_rejects_zero(self) -> None:
        """A zero access-token lifetime is rejected at startup."""
        with self.assertRaises(ValidationError):
            Settings(jwt_secret_key=TEST_SECRET, access_token_expire_minutes=0)

    def test_access_token_lifetime_rejects_negative(self) -> None:
        """A negative access-token lifetime is rejected at startup."""
        with self.assertRaises(ValidationError):
            Settings(jwt_secret_key=TEST_SECRET, access_token_expire_minutes=-5)

    def test_refresh_token_lifetime_rejects_zero(self) -> None:
        """A zero refresh-token lifetime is rejected at startup."""
        with self.assertRaises(ValidationError):
            Settings(jwt_secret_key=TEST_SECRET, refresh_token_expire_minutes=0)

    def test_refresh_token_lifetime_rejects_negative(self) -> None:
        """A negative refresh-token lifetime is rejected at startup."""
        with self.assertRaises(ValidationError):
            Settings(jwt_secret_key=TEST_SECRET, refresh_token_expire_minutes=-5)

    def test_refresh_lifetime_must_exceed_access_lifetime(self) -> None:
        """A refresh lifetime equal to or shorter than access is rejected."""
        with self.assertRaises(ValidationError):
            Settings(
                jwt_secret_key=TEST_SECRET,
                access_token_expire_minutes=15,
                refresh_token_expire_minutes=15,
            )
        with self.assertRaises(ValidationError):
            Settings(
                jwt_secret_key=TEST_SECRET,
                access_token_expire_minutes=30,
                refresh_token_expire_minutes=15,
            )


class ModuleFunctionTests(unittest.TestCase):
    """The module-level API is wired to the application settings."""

    def test_module_access_token_round_trip(self) -> None:
        """create_access_token/decode_token work through the settings path."""
        token = create_access_token(_USER_ID)
        claims = decode_token(token)
        self.assertEqual(claims.user_id, _USER_ID)
        self.assertEqual(claims.token_type, TokenType.ACCESS)

    def test_module_validate_access_token(self) -> None:
        """validate_access_token works through the settings path."""
        claims = validate_access_token(create_access_token(_USER_ID))
        self.assertEqual(claims.user_id, _USER_ID)

    def test_module_validate_refresh_token(self) -> None:
        """validate_refresh_token works through the settings path."""
        claims = validate_refresh_token(create_refresh_token(_USER_ID))
        self.assertEqual(claims.token_type, TokenType.REFRESH)


if __name__ == "__main__":
    unittest.main()
