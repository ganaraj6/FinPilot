"""Reusable authentication dependencies for protected routes.

``get_current_user`` reads the access token from the HttpOnly cookie,
validates it, and returns the active User entity. It is designed to be
used as a FastAPI ``Depends()`` on any endpoint that requires an
authenticated caller.

``get_auth_service`` builds the AuthService from the request-scoped
database session. It lives here so both the router and ``get_current_user``
share the same callable — FastAPI dependency overrides applied to one
are visible to the other.
"""

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.exceptions import (
    ExpiredTokenError,
    InvalidCredentialsError,
    InvalidTokenError,
    InvalidTokenTypeError,
)
from app.core.tokens import validate_access_token
from app.database.session import get_db
from app.modules.auth.cookies import ACCESS_TOKEN_COOKIE
from app.modules.auth.models import User
from app.modules.auth.repository import UserRepository
from app.modules.auth.service import AuthService


def get_auth_service(db: Session = Depends(get_db)) -> AuthService:  # noqa: B008
    """Build the auth service for the current request.

    Args:
        db: The request-scoped database session provided by get_db.

    Returns:
        An AuthService bound to the session and its user repository.
    """
    return AuthService(db, UserRepository(db))


async def get_current_user(
    request: Request,
    service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> User:
    """Return the authenticated user or raise 401.

    The access token is read exclusively from the HttpOnly cookie. Token
    validation and user lookup failures all produce the same generic 401
    response so callers cannot enumerate valid accounts or distinguish
    failure reasons.

    Args:
        request: The incoming HTTP request carrying the access-token cookie.
        service: AuthService providing user lookup for access-token validation.

    Returns:
        The active User entity.

    Raises:
        HTTPException: 401 if the cookie is missing, the token is
            invalid/expired/wrong-type, or the user does not exist or is
            inactive.
    """
    access_token_value = request.cookies.get(ACCESS_TOKEN_COOKIE)
    if access_token_value is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    try:
        claims = validate_access_token(access_token_value)
    except (InvalidTokenError, ExpiredTokenError, InvalidTokenTypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        ) from exc

    try:
        user = service.get_user_for_access(claims.user_id)
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        ) from exc

    return user
