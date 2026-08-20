"""Tests for the auth HTTP router (registration and login).

The router is tested end to end through Starlette's TestClient with the real
``get_auth_service`` dependency overridden by a fake, so no database is touched.
The fake asserts that the router stays thin: requests are forwarded verbatim
(normalization belongs to the service) and the router delegates to the service.
Login additionally verifies the HttpOnly-cookie delivery of the access and
refresh tokens and the mapping of authentication errors to HTTP status codes.

The real ``app.main.app`` is imported so prefix composition (``/api/v1``) and
router mounting are exercised exactly as in production.

``starlette.testclient`` requires ``httpx2`` (installed via
``requirements-dev.txt``), so the HTTP tests are skipped when it is missing.
"""

# ruff: noqa: E402

import importlib.util
import os
import sys
import unittest
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-auth-router-tests-0123456789"
os.environ["ENVIRONMENT"] = "development"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config.settings import get_settings
from app.core.exceptions import (
    AccountLockedError,
    EmailAlreadyRegisteredError,
    InactiveAccountError,
    InvalidCredentialsError,
)
from app.core.tokens import (
    TokenType,
    create_access_token,
    create_refresh_token,
    validate_access_token,
    validate_refresh_token,
)
from app.main import app
from app.modules.auth.cookies import ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE
from app.modules.auth.router import get_auth_service
from app.modules.auth.schemas import AuthenticatedUserResponse
from app.modules.auth.service import AuthService

_HAS_HTTP_CLIENT = (
    importlib.util.find_spec("httpx2") is not None or importlib.util.find_spec("httpx") is not None
)

REGISTER_PATH = "/api/v1/auth/register"
LOGIN_PATH = "/api/v1/auth/login"

_PAYLOAD = {
    "full_name": "Test User",
    "email": "user@example.com",
    "password": "Password123!",
}

_LOGIN_PAYLOAD = {
    "email": "user@example.com",
    "password": "Password123!",
}


def _registration_response(*, email="user@example.com"):
    """Build the AuthenticatedUserResponse the fake service returns."""
    return AuthenticatedUserResponse(
        id=uuid.uuid4(),
        full_name="Test User",
        email=email,
        profile_photo_url=None,
        currency="USD",
        timezone="UTC",
        onboarding_completed=False,
        is_active=True,
        email_verified_at=None,
        created_at=datetime.now(UTC),
    )


def _parse_cookie(header):
    """Split a Set-Cookie header into name, value, and attribute dict."""
    parts = [part.strip() for part in header.split(";")]
    name, value = parts[0].split("=", 1)
    attributes = {}
    for part in parts[1:]:
        if not part:
            continue
        if "=" in part:
            key, _, raw_value = part.partition("=")
            attributes[key.strip().lower()] = raw_value.strip()
        else:
            attributes[part.lower()] = True
    return name, value, attributes


def _cookie_map(response):
    """Map cookie names to (value, attributes) from a response's Set-Cookie headers."""
    cookies = {}
    raw_headers = getattr(response, "raw_headers", None)
    if raw_headers is not None:
        headers = [
            value.decode("latin-1")
            for key, value in raw_headers
            if key.decode("latin-1").lower() == "set-cookie"
        ]
    else:
        headers = response.headers.get_list("set-cookie")
    for header in headers:
        name, value, attributes = _parse_cookie(header)
        cookies[name] = (value, attributes)
    return cookies


class FakeAuthService:
    """Thin stand-in for AuthService used to isolate the router."""

    def __init__(self) -> None:
        """Initialize the fake with empty call recording."""
        self.register_calls: list = []
        self.registration_error: Exception | None = None
        self.login_calls: list = []
        self.login_error: Exception | None = None
        self.last_response: AuthenticatedUserResponse | None = None

    def register(self, request):
        """Record the request, then honor the configured error or return a profile."""
        self.register_calls.append(request)
        if self.registration_error is not None:
            raise self.registration_error
        self.last_response = _registration_response(email=str(request.email))
        return self.last_response

    def login(self, request):
        """Record the request, then honor the configured error or return a profile."""
        self.login_calls.append(request)
        if self.login_error is not None:
            raise self.login_error
        self.last_response = _registration_response(email=str(request.email))
        return self.last_response


if _HAS_HTTP_CLIENT:
    from starlette.testclient import TestClient


@unittest.skipUnless(_HAS_HTTP_CLIENT, "httpx2 (or httpx) is required for TestClient")
class RegisterEndpointTests(unittest.TestCase):
    """POST /api/v1/auth/register HTTP behaviour."""

    def setUp(self) -> None:
        """Wire the fake service into the app and create a test client."""
        self.service = FakeAuthService()
        self.previous_override = app.dependency_overrides.get(get_auth_service)
        app.dependency_overrides[get_auth_service] = lambda: self.service
        self.client = TestClient(app, raise_server_exceptions=False)

    def tearDown(self) -> None:
        """Restore the original dependency override state."""
        if self.previous_override is None:
            app.dependency_overrides.pop(get_auth_service, None)
        else:
            app.dependency_overrides[get_auth_service] = self.previous_override

    def test_register_returns_201_with_safe_profile(self):
        """A valid registration returns 201 and the profile returned by the service."""
        response = self.client.post(REGISTER_PATH, json=_PAYLOAD)

        self.assertEqual(response.status_code, 201)
        self.assertIsNotNone(self.service.last_response)
        self.assertEqual(response.json(), self.service.last_response.model_dump(mode="json"))

    def test_response_contains_no_credentials(self):
        """The response body never contains the password or its hash."""
        response = self.client.post(REGISTER_PATH, json=_PAYLOAD)

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertNotIn("password", body)
        self.assertNotIn("password_hash", body)

    def test_duplicate_email_returns_409(self):
        """A duplicate registration maps to a 409 conflict response."""
        self.service.registration_error = EmailAlreadyRegisteredError()

        response = self.client.post(REGISTER_PATH, json=_PAYLOAD)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json(), {"detail": "Email already registered"})
        self.assertEqual(len(self.service.register_calls), 1)

    def test_email_is_forwarded_as_parsed_by_schema(self):
        """The router forwards the parsed email; full normalization stays in the service.

        pydantic's EmailStr strips whitespace and lowercases the domain, so the
        router hands the service ``User@example.com``. Lowercasing the local part
        (the full ``user@example.com`` normalization) remains the service's job.
        """
        response = self.client.post(
            REGISTER_PATH, json={**_PAYLOAD, "email": "  User@Example.COM  "}
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(str(self.service.register_calls[-1].email), "User@example.com")

    def test_registration_is_delegated_to_service(self):
        """The router forwards the whole payload to the service."""
        self.client.post(REGISTER_PATH, json=_PAYLOAD)

        self.assertEqual(len(self.service.register_calls), 1)
        forwarded = self.service.register_calls[-1]
        self.assertEqual(forwarded.full_name, _PAYLOAD["full_name"])
        self.assertEqual(str(forwarded.email), _PAYLOAD["email"])
        self.assertEqual(forwarded.password, _PAYLOAD["password"])

    def test_missing_body_returns_422(self):
        """An empty body fails schema validation with 422."""
        response = self.client.post(REGISTER_PATH, json={})

        self.assertEqual(response.status_code, 422)
        self.assertEqual(len(self.service.register_calls), 0)

    def test_unexpected_service_error_propagates(self):
        """A non-domain service error surfaces as a 500, not a 409."""
        self.service.registration_error = RuntimeError("boom")

        response = self.client.post(REGISTER_PATH, json=_PAYLOAD)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(len(self.service.register_calls), 1)


class LoginEndpointTests(unittest.TestCase):
    """POST /api/v1/auth/login HTTP behaviour and cookie security."""

    def setUp(self) -> None:
        """Wire the fake service into the app and create a test client."""
        self.service = FakeAuthService()
        self.previous_override = app.dependency_overrides.get(get_auth_service)
        app.dependency_overrides[get_auth_service] = lambda: self.service
        self.client = TestClient(app, raise_server_exceptions=False)

    def tearDown(self) -> None:
        """Restore the original dependency override state."""
        if self.previous_override is None:
            app.dependency_overrides.pop(get_auth_service, None)
        else:
            app.dependency_overrides[get_auth_service] = self.previous_override

    def _login(self):
        """POST the login payload through the test client."""
        return self.client.post(LOGIN_PATH, json=_LOGIN_PAYLOAD)

    def test_login_returns_200(self):
        """A successful login returns 200 OK."""
        response = self._login()

        self.assertEqual(response.status_code, 200)

    def test_login_returns_authenticated_user_response(self):
        """The login body is exactly the safe profile returned by the service."""
        response = self._login()

        self.assertEqual(response.json(), self.service.last_response.model_dump(mode="json"))

    def test_login_sets_access_token_cookie(self):
        """A successful login stores the access token in a cookie."""
        response = self._login()

        self.assertIn(ACCESS_TOKEN_COOKIE, _cookie_map(response))

    def test_login_sets_refresh_token_cookie(self):
        """A successful login stores the refresh token in a cookie."""
        response = self._login()

        self.assertIn(REFRESH_TOKEN_COOKIE, _cookie_map(response))

    def test_access_token_cookie_is_httponly(self):
        """The access-token cookie is not readable from JavaScript."""
        _, attributes = _cookie_map(self._login())[ACCESS_TOKEN_COOKIE]

        self.assertIs(attributes.get("httponly"), True)

    def test_refresh_token_cookie_is_httponly(self):
        """The refresh-token cookie is not readable from JavaScript."""
        _, attributes = _cookie_map(self._login())[REFRESH_TOKEN_COOKIE]

        self.assertIs(attributes.get("httponly"), True)

    def test_cookie_samesite_is_lax(self):
        """Both auth cookies are sent with SameSite=lax."""
        cookies = _cookie_map(self._login())

        for name in (ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE):
            _, attributes = cookies[name]
            self.assertEqual(attributes.get("samesite"), "lax")

    def test_cookie_max_age_matches_token_lifetime(self):
        """Cookie max-age mirrors the configured token lifetimes."""
        settings = get_settings()
        cookies = _cookie_map(self._login())

        access_max_age = str(settings.access_token_expire_minutes * 60)
        self.assertEqual(cookies[ACCESS_TOKEN_COOKIE][1].get("max-age"), access_max_age)

        refresh_max_age = str(settings.refresh_token_expire_minutes * 60)
        self.assertEqual(cookies[REFRESH_TOKEN_COOKIE][1].get("max-age"), refresh_max_age)

    def test_development_cookies_do_not_require_https(self):
        """Development cookies omit the Secure flag so plain HTTP works."""
        cookies = _cookie_map(self._login())

        for name in (ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE):
            _, attributes = cookies[name]
            self.assertNotIn("secure", attributes)

    def test_production_cookies_require_https(self):
        """Production cookies carry the Secure flag."""
        settings = get_settings()
        with mock.patch.object(settings, "environment", "production"):
            cookies = _cookie_map(self._login())

        for name in (ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE):
            _, attributes = cookies[name]
            self.assertIs(attributes.get("secure"), True)

    def test_invalid_credentials_return_401(self):
        """Invalid credentials map to 401 without revealing which field failed."""
        self.service.login_error = InvalidCredentialsError()

        response = self._login()

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Invalid email or password"})

    def test_locked_account_returns_423(self):
        """A locked account maps to 423 without revealing the lock window."""
        self.service.login_error = AccountLockedError()

        response = self._login()

        self.assertEqual(response.status_code, 423)
        self.assertEqual(response.json(), {"detail": "Account is temporarily locked"})

    def test_inactive_account_returns_403(self):
        """An inactive account maps to 403 without revealing account state."""
        self.service.login_error = InactiveAccountError()

        response = self._login()

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"detail": "Account is inactive"})

    def test_failed_login_sets_no_cookies(self):
        """Failed authentication never attaches authentication cookies."""
        for error in (InvalidCredentialsError(), AccountLockedError(), InactiveAccountError()):
            with self.subTest(error=type(error).__name__):
                self.service.login_error = error
                response = self._login()

                self.assertGreaterEqual(response.status_code, 400)
                self.assertEqual(response.headers.get_list("set-cookie"), [])

    def test_failed_login_creates_no_tokens(self):
        """Failed authentication never generates tokens."""
        with (
            mock.patch("app.modules.auth.router.create_access_token") as create_access,
            mock.patch("app.modules.auth.router.create_refresh_token") as create_refresh,
        ):
            self.service.login_error = InvalidCredentialsError()
            response = self._login()

            self.assertEqual(response.status_code, 401)
            create_access.assert_not_called()
            create_refresh.assert_not_called()

    def test_response_json_contains_no_access_token(self):
        """The JSON body never contains the access token."""
        response = self._login()

        self.assertNotIn("access_token", response.json())

    def test_response_json_contains_no_refresh_token(self):
        """The JSON body never contains the refresh token."""
        response = self._login()

        self.assertNotIn("refresh_token", response.json())

    def test_response_json_contains_no_password(self):
        """The JSON body never contains the plaintext password."""
        response = self._login()

        self.assertNotIn("password", response.json())

    def test_response_json_contains_no_password_hash(self):
        """The JSON body never contains the password hash."""
        response = self._login()

        self.assertNotIn("password_hash", response.json())

    def test_login_delegates_request_to_service(self):
        """The router forwards the parsed login payload to the service."""
        self._login()

        self.assertEqual(len(self.service.login_calls), 1)
        forwarded = self.service.login_calls[0]
        self.assertEqual(str(forwarded.email), _LOGIN_PAYLOAD["email"])
        self.assertEqual(forwarded.password, _LOGIN_PAYLOAD["password"])

    def test_access_token_cookie_is_a_valid_access_token(self):
        """The access cookie holds a signed access JWT for the logged-in user."""
        value, _ = _cookie_map(self._login())[ACCESS_TOKEN_COOKIE]

        claims = validate_access_token(value)

        self.assertEqual(claims.user_id, self.service.last_response.id)
        self.assertIs(claims.token_type, TokenType.ACCESS)

    def test_refresh_token_cookie_is_a_valid_refresh_token(self):
        """The refresh cookie holds a signed refresh JWT for the logged-in user."""
        value, _ = _cookie_map(self._login())[REFRESH_TOKEN_COOKIE]

        claims = validate_refresh_token(value)

        self.assertEqual(claims.user_id, self.service.last_response.id)
        self.assertIs(claims.token_type, TokenType.REFRESH)

    def test_unexpected_service_error_is_not_an_auth_error(self):
        """Unexpected errors surface as 500, never as 401/403/423."""
        self.service.login_error = RuntimeError("boom")

        response = self._login()

        self.assertEqual(response.status_code, 500)
        self.assertNotIn(response.status_code, (401, 403, 423))


class RouterRegistrationTests(unittest.TestCase):
    """Mounting and dependency wiring (no HTTP client required)."""

    def test_registration_route_is_mounted_with_api_prefix(self):
        """The register route is reachable at the composed /api/v1 path."""
        paths = app.openapi()["paths"]
        self.assertIn(REGISTER_PATH, paths)

    def test_registration_route_only_accepts_post(self):
        """The register route exposes only the POST method."""
        path_spec = app.openapi()["paths"][REGISTER_PATH]
        self.assertEqual(set(path_spec), {"post"})

    def test_login_route_is_mounted_with_api_prefix(self):
        """The login route is reachable at the composed /api/v1 path."""
        paths = app.openapi()["paths"]
        self.assertIn(LOGIN_PATH, paths)

    def test_login_route_only_accepts_post(self):
        """The login route exposes only the POST method."""
        path_spec = app.openapi()["paths"][LOGIN_PATH]
        self.assertEqual(set(path_spec), {"post"})

    def test_get_auth_service_wires_session_into_repository(self):
        """get_auth_service builds an AuthService bound to the request session."""
        db = object()

        service = get_auth_service(db)

        self.assertIsInstance(service, AuthService)
        self.assertIs(service._db, db)

    def test_refresh_route_is_mounted_with_api_prefix(self):
        """The refresh route is reachable at the composed /api/v1 path."""
        paths = app.openapi()["paths"]
        self.assertIn(REFRESH_PATH, paths)

    def test_refresh_route_only_accepts_post(self):
        """The refresh route exposes only the POST method."""
        path_spec = app.openapi()["paths"][REFRESH_PATH]
        self.assertEqual(set(path_spec), {"post"})


REFRESH_PATH = "/api/v1/auth/refresh"


def _make_user_entity(*, user_id=None, is_active=True):
    """Build a minimal User-like object for repository fakes."""

    class _User:
        pass

    u = _User()
    u.id = user_id or uuid.uuid4()
    u.is_active = is_active
    u.full_name = "Test User"
    u.email = "user@example.com"
    u.profile_photo_url = None
    u.currency = "USD"
    u.timezone = "UTC"
    u.onboarding_completed = False
    u.email_verified_at = None
    u.created_at = datetime.now(UTC)
    return u


class FakeRefreshRepository:
    """Repository fake that returns a preconfigured user for get_by_id."""

    def __init__(self, user):
        """Store the user and record get_by_id calls."""
        self._user = user
        self.get_by_id_calls: list = []

    def get_by_id(self, user_id):
        """Record the call and return the stored user only when ID matches."""
        self.get_by_id_calls.append(user_id)
        if user_id != self._user.id:
            return None
        return self._user


class FakeRefreshAuthService:
    """Minimal AuthService stand-in for refresh tests exposing user lookup."""

    def __init__(self, repository):
        """Store the repository for user lookup."""
        self._repository = repository

    def get_user_for_refresh(self, user_id):
        """Delegate to repository and reject missing/inactive users."""
        user = self._repository.get_by_id(user_id)
        if user is None or not user.is_active:
            raise InvalidCredentialsError()
        return user


class RefreshEndpointTests(unittest.TestCase):
    """POST /api/v1/auth/refresh HTTP behaviour."""

    def setUp(self) -> None:
        """Wire a fake service with a user entity and create a test client."""
        self.user = _make_user_entity()
        self.repo = FakeRefreshRepository(self.user)
        self.service = FakeRefreshAuthService(self.repo)
        self.previous_override = app.dependency_overrides.get(get_auth_service)
        app.dependency_overrides[get_auth_service] = lambda: self.service
        self.client = TestClient(app, raise_server_exceptions=False)

    def tearDown(self) -> None:
        """Restore the original dependency override state."""
        if self.previous_override is None:
            app.dependency_overrides.pop(get_auth_service, None)
        else:
            app.dependency_overrides[get_auth_service] = self.previous_override

    def _valid_refresh_cookie(self, user_id=None):
        """Return a cookie dict containing a valid refresh token."""
        uid = user_id or self.user.id
        token = create_refresh_token(uid)
        return {REFRESH_TOKEN_COOKIE: token}

    def test_valid_refresh_returns_200(self):
        """A valid refresh cookie returns 200 OK."""
        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        self.assertEqual(response.status_code, 200)

    def test_valid_refresh_returns_authenticated_user_response(self):
        """The refresh body is the safe profile for the user."""
        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        expected = AuthenticatedUserResponse.model_validate(self.user).model_dump(mode="json")
        self.assertEqual(response.json(), expected)

    def test_valid_refresh_sets_new_access_token_cookie(self):
        """A successful refresh sets a new access token cookie."""
        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        cookies = _cookie_map(response)
        self.assertIn(ACCESS_TOKEN_COOKIE, cookies)

    def test_refresh_does_not_set_refresh_token_cookie(self):
        """A successful refresh does not overwrite the refresh token cookie."""
        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        raw_headers = getattr(response, "raw_headers", None)
        if raw_headers is not None:
            headers = [
                value.decode("latin-1")
                for key, value in raw_headers
                if key.decode("latin-1").lower() == "set-cookie"
            ]
        else:
            headers = response.headers.get_list("set-cookie")
        for header in headers:
            name = header.split("=")[0].strip()
            self.assertNotEqual(name, REFRESH_TOKEN_COOKIE)

    def test_new_access_token_validates_successfully(self):
        """The new access cookie holds a valid signed access JWT."""
        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        value, _ = _cookie_map(response)[ACCESS_TOKEN_COOKIE]
        claims = validate_access_token(value)

        self.assertEqual(claims.user_id, self.user.id)

    def test_new_access_token_has_correct_user_id(self):
        """The new access token carries the correct user ID."""
        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        value, _ = _cookie_map(response)[ACCESS_TOKEN_COOKIE]
        claims = validate_access_token(value)

        self.assertEqual(claims.user_id, self.user.id)

    def test_new_access_token_has_token_type_access(self):
        """The new access token has token_type=access."""
        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        value, _ = _cookie_map(response)[ACCESS_TOKEN_COOKIE]
        claims = validate_access_token(value)

        self.assertIs(claims.token_type, TokenType.ACCESS)

    def test_missing_refresh_token_cookie_returns_401(self):
        """A missing refresh cookie returns 401."""
        response = self.client.post(REFRESH_PATH)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Invalid or expired refresh token"})

    def test_malformed_refresh_token_returns_401(self):
        """A malformed refresh token returns 401."""
        response = self.client.post(REFRESH_PATH, cookies={REFRESH_TOKEN_COOKIE: "not.a.jwt"})

        self.assertEqual(response.status_code, 401)

    def test_expired_refresh_token_returns_401(self):
        """An expired refresh token returns 401."""
        from app.config.settings import Settings

        test_settings = Settings(
            jwt_secret_key="test-secret-key-for-auth-router-tests-0123456789",
            jwt_algorithm="HS256",
            access_token_expire_minutes=15,
            refresh_token_expire_minutes=60 * 24 * 14,
        )
        payload = {
            "sub": str(self.user.id),
            "token_type": "refresh",
            "jti": str(uuid.uuid4()),
            "iat": datetime(2020, 1, 1, tzinfo=UTC),
            "exp": datetime(2020, 1, 1, 1, tzinfo=UTC),
        }
        import jwt

        expired_token = jwt.encode(
            payload,
            test_settings.jwt_secret_key.get_secret_value(),
            algorithm=test_settings.jwt_algorithm,
        )
        response = self.client.post(REFRESH_PATH, cookies={REFRESH_TOKEN_COOKIE: expired_token})

        self.assertEqual(response.status_code, 401)

    def test_access_token_as_refresh_returns_401(self):
        """An access token supplied as a refresh token returns 401."""
        access_token = create_access_token(self.user.id)
        response = self.client.post(REFRESH_PATH, cookies={REFRESH_TOKEN_COOKIE: access_token})

        self.assertEqual(response.status_code, 401)

    def test_tampered_refresh_token_returns_401(self):
        """A tampered refresh token returns 401."""
        token = create_refresh_token(self.user.id)
        tampered = token[:-5] + "XXXXX"
        response = self.client.post(REFRESH_PATH, cookies={REFRESH_TOKEN_COOKIE: tampered})

        self.assertEqual(response.status_code, 401)

    def test_invalid_signature_returns_401(self):
        """A refresh token signed with the wrong secret returns 401."""
        from app.config.settings import Settings
        from app.core.tokens import TokenService

        wrong_settings = Settings(
            jwt_secret_key="wrong-secret-key-that-is-long-enough-0000",
            jwt_algorithm="HS256",
            access_token_expire_minutes=15,
            refresh_token_expire_minutes=60 * 24 * 14,
        )
        ts = TokenService(wrong_settings)
        token_with_wrong_sig = ts.create_refresh_token(self.user.id)
        response = self.client.post(
            REFRESH_PATH, cookies={REFRESH_TOKEN_COOKIE: token_with_wrong_sig}
        )

        self.assertEqual(response.status_code, 401)

    def test_user_not_found_returns_401(self):
        """A refresh token for a nonexistent user returns 401."""
        other_id = uuid.uuid4()
        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie(other_id))

        self.assertEqual(response.status_code, 401)

    def test_inactive_user_returns_401(self):
        """A refresh token for an inactive user returns 401."""
        inactive_user = _make_user_entity(is_active=False)
        self.repo._user = inactive_user
        response = self.client.post(
            REFRESH_PATH, cookies=self._valid_refresh_cookie(inactive_user.id)
        )

        self.assertEqual(response.status_code, 401)

    def test_failed_refresh_sets_no_access_token_cookie(self):
        """A failed refresh does not set an access token cookie."""
        response = self.client.post(REFRESH_PATH)

        raw_headers = getattr(response, "raw_headers", None)
        if raw_headers is not None:
            headers = [
                value.decode("latin-1")
                for key, value in raw_headers
                if key.decode("latin-1").lower() == "set-cookie"
            ]
        else:
            headers = response.headers.get_list("set-cookie")
        for header in headers:
            name = header.split("=")[0].strip()
            self.assertNotEqual(name, ACCESS_TOKEN_COOKIE)

    def test_failed_refresh_does_not_modify_refresh_cookie(self):
        """A failed refresh does not overwrite the refresh token cookie."""
        response = self.client.post(REFRESH_PATH, cookies={REFRESH_TOKEN_COOKIE: "invalid"})

        self.assertEqual(response.status_code, 401)
        cookies = _cookie_map(response)
        self.assertNotIn(REFRESH_TOKEN_COOKIE, cookies)

    def test_response_json_is_safe_profile(self):
        """The response JSON is the safe user profile with no sensitive fields."""
        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        body = response.json()
        self.assertIn("id", body)
        self.assertIn("email", body)
        self.assertNotIn("password", body)
        self.assertNotIn("password_hash", body)

    def test_response_json_contains_no_jwt_strings(self):
        """The response JSON contains no JWT token strings."""
        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        body_str = str(response.json())
        self.assertNotRegex(body_str, r"eyJ")

    def test_refresh_delegates_user_lookup_to_public_service_method(self):
        """The router delegates user lookup to the public AuthService method."""
        self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        self.assertEqual(len(self.repo.get_by_id_calls), 1)
        self.assertEqual(self.repo.get_by_id_calls[0], self.user.id)

    def test_router_does_not_access_service_private_repository(self):
        """Refresh works even when _repository is inaccessible on the service."""
        user = self.user

        class ServiceWithoutRepository:
            """Service that only exposes the public get_user_for_refresh method."""

            def get_user_for_refresh(self, user_id):
                if user_id != user.id or not user.is_active:
                    raise InvalidCredentialsError()
                return user

        app.dependency_overrides[get_auth_service] = lambda: ServiceWithoutRepository()

        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        self.assertEqual(response.status_code, 200)

    def test_unexpected_error_is_not_401(self):
        """Unexpected internal errors propagate as 500, not 401."""
        self.repo.get_by_id = lambda uid: (_ for _ in ()).throw(RuntimeError("boom"))

        response = self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        self.assertEqual(response.status_code, 500)

    def test_refresh_does_not_call_service_login(self):
        """Refresh never delegates to AuthService.login."""
        self.service.login = lambda req: (_ for _ in ()).should_not_be_called()
        self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie())

        self.assertFalse(hasattr(self.service, "_login_called"))

    def test_refresh_does_not_modify_authentication_state(self):
        """Refresh does not update last_login_at, failed_login_attempts, or locked_until."""
        user = _make_user_entity()
        repo = FakeRefreshRepository(user)
        service = FakeRefreshAuthService(repo)
        app.dependency_overrides[get_auth_service] = lambda: service

        self.client.post(REFRESH_PATH, cookies=self._valid_refresh_cookie(user.id))

        self.assertIsNone(getattr(user, "last_login_at", None))
        self.assertEqual(getattr(user, "failed_login_attempts", 0), 0)
        self.assertIsNone(getattr(user, "locked_until", None))


if __name__ == "__main__":
    unittest.main()
