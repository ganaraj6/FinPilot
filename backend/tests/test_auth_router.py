"""Tests for the auth registration HTTP router.

The router is tested end to end through Starlette's TestClient with the real
``get_auth_service`` dependency overridden by a fake, so no database is touched.
The fake asserts that the router stays thin: requests are forwarded verbatim
(normalization belongs to the service) and the router delegates to the service.

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

os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-auth-router-tests-0123456789"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.exceptions import EmailAlreadyRegisteredError
from app.main import app
from app.modules.auth.router import get_auth_service
from app.modules.auth.schemas import AuthenticatedUserResponse
from app.modules.auth.service import AuthService

_HAS_HTTP_CLIENT = (
    importlib.util.find_spec("httpx2") is not None or importlib.util.find_spec("httpx") is not None
)

REGISTER_PATH = "/api/v1/auth/register"

_PAYLOAD = {
    "full_name": "Test User",
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


class FakeAuthService:
    """Thin stand-in for AuthService used to isolate the router."""

    def __init__(self) -> None:
        """Initialize the fake with empty call recording."""
        self.register_calls: list = []
        self.registration_error: Exception | None = None
        self.last_response: AuthenticatedUserResponse | None = None

    def register(self, request):
        """Record the request, then honor the configured error or return a profile."""
        self.register_calls.append(request)
        if self.registration_error is not None:
            raise self.registration_error
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

    def test_get_auth_service_wires_session_into_repository(self):
        """get_auth_service builds an AuthService bound to the request session."""
        db = object()

        service = get_auth_service(db)

        self.assertIsInstance(service, AuthService)
        self.assertIs(service._db, db)


if __name__ == "__main__":
    unittest.main()
