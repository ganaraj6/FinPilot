"""HTTP cookie conventions for the auth module.

Tokens are delivered exclusively through HttpOnly cookies and never appear in
JSON response bodies. This module owns the cookie names, paths, and attributes
so the router stays thin and future endpoints (refresh, logout) reuse a single
source of truth for cookie handling.

Cookie paths are deliberately scoped:
- The access-token cookie is sent to every API route (``/api/v1``) because it
  guards all protected endpoints.
- The refresh-token cookie is limited to the auth route group (``/api/v1/auth``)
  because it is only ever presented to the authentication endpoints, including
  the future ``POST /api/v1/auth/refresh``.
"""

from __future__ import annotations

from starlette.responses import Response

from app.config.settings import Settings

ACCESS_TOKEN_COOKIE = "access_token"
"""Name of the HttpOnly cookie carrying the signed access token."""

REFRESH_TOKEN_COOKIE = "refresh_token"
"""Name of the HttpOnly cookie carrying the signed refresh token."""

_SAMESITE = "lax"


def access_token_cookie_path(settings: Settings) -> str:
    """Return the cookie path for the access token.

    The access token protects the whole API, so the cookie is sent to every
    route under the API prefix.

    Args:
        settings: Application settings providing the API prefix.

    Returns:
        The cookie path for the access-token cookie.
    """
    return settings.api_v1_prefix


def refresh_token_cookie_path(settings: Settings) -> str:
    """Return the cookie path for the refresh token.

    The refresh token is only consumed by authentication endpoints, so the
    cookie is restricted to the auth route group under the API prefix. The
    future ``POST /api/v1/auth/refresh`` endpoint lives under this path.

    Args:
        settings: Application settings providing the API prefix.

    Returns:
        The cookie path for the refresh-token cookie.
    """
    return f"{settings.api_v1_prefix}/auth"


def _secure_cookie(settings: Settings) -> bool:
    """Return whether cookies must be marked Secure.

    Only the production environment requires HTTPS; local development over HTTP
    stays usable with plain cookies.

    Args:
        settings: Application settings identifying the environment.

    Returns:
        True only when the environment is production.
    """
    return settings.environment.lower() == "production"


def set_auth_cookies(
    response: Response,
    *,
    access_token: str,
    refresh_token: str,
    settings: Settings,
) -> None:
    """Attach the access and refresh tokens to a response as HttpOnly cookies.

    The cookies are JavaScript-inaccessible, restricted to SameSite=lax, scoped
    to their documented paths, and their max-age mirrors the configured token
    lifetimes. Secure is applied only in production.

    Args:
        response: The response the Set-Cookie headers are attached to.
        access_token: Signed JWT access token to store.
        refresh_token: Signed JWT refresh token to store.
        settings: Application settings providing cookie attributes and token
            lifetimes.
    """
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access_token,
        max_age=settings.access_token_expire_minutes * 60,
        path=access_token_cookie_path(settings),
        secure=_secure_cookie(settings),
        httponly=True,
        samesite=_SAMESITE,
    )
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=refresh_token,
        max_age=settings.refresh_token_expire_minutes * 60,
        path=refresh_token_cookie_path(settings),
        secure=_secure_cookie(settings),
        httponly=True,
        samesite=_SAMESITE,
    )


def set_access_token_cookie(
    response: Response,
    *,
    access_token: str,
    settings: Settings,
) -> None:
    """Attach only the access token to a response as an HttpOnly cookie.

    Used by the refresh endpoint which replaces the access token while leaving
    the refresh-token cookie untouched.

    Args:
        response: The response the Set-Cookie header is attached to.
        access_token: Signed JWT access token to store.
        settings: Application settings providing cookie attributes and the
            access-token lifetime.
    """
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access_token,
        max_age=settings.access_token_expire_minutes * 60,
        path=access_token_cookie_path(settings),
        secure=_secure_cookie(settings),
        httponly=True,
        samesite=_SAMESITE,
    )
