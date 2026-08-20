"""HTTP router for the auth module.

The router is intentionally thin: it validates HTTP input, builds the auth
service from the existing database session dependency, delegates business logic
to AuthService, and translates known domain exceptions into HTTP responses.
No business logic (email normalization, password hashing, duplicate detection)
lives here.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.config.settings import get_settings
from app.core.exceptions import (
    AccountLockedError,
    EmailAlreadyRegisteredError,
    ExpiredTokenError,
    InactiveAccountError,
    InvalidCredentialsError,
    InvalidTokenError,
    InvalidTokenTypeError,
)
from app.core.tokens import (
    create_access_token,
    create_refresh_token,
    validate_refresh_token,
)
from app.database.session import get_db
from app.modules.auth.cookies import (
    REFRESH_TOKEN_COOKIE,
    set_access_token_cookie,
    set_auth_cookies,
)
from app.modules.auth.repository import UserRepository
from app.modules.auth.schemas import (
    AuthenticatedUserResponse,
    UserLoginRequest,
    UserRegistrationRequest,
)
from app.modules.auth.service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


def get_auth_service(db: Session = Depends(get_db)) -> AuthService:
    """Build the auth service for the current request.

    Args:
        db: The request-scoped database session provided by get_db.

    Returns:
        An AuthService bound to the session and its user repository.
    """
    return AuthService(db, UserRepository(db))


@router.post(
    "/register",
    response_model=AuthenticatedUserResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_409_CONFLICT: {"description": "The email address is already registered"}
    },
    summary="Register a new user",
)
def register(
    request: UserRegistrationRequest,
    service: AuthService = Depends(get_auth_service),
) -> AuthenticatedUserResponse:
    """Create a new user account.

    Args:
        request: Registration payload with full name, email, and password.
        service: AuthService that performs the registration.

    Returns:
        The safe authenticated-user profile.

    Raises:
        HTTPException: 409 Conflict if the email is already registered.
    """
    try:
        return service.register(request)
    except EmailAlreadyRegisteredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        ) from exc


@router.post(
    "/login",
    response_model=AuthenticatedUserResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid email or password"},
        status.HTTP_403_FORBIDDEN: {"description": "Account is inactive"},
        status.HTTP_423_LOCKED: {"description": "Account is temporarily locked"},
    },
    summary="Log in with email and password",
)
def login(
    request: UserLoginRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),
) -> AuthenticatedUserResponse:
    """Authenticate a user and set the authentication cookies.

    Args:
        request: Login payload with email and password.
        response: The response the authentication cookies are attached to.
        service: AuthService that performs credential verification and updates
            authentication state.

    Returns:
        The safe authenticated-user profile; tokens travel only in cookies.

    Raises:
        HTTPException: 401 for invalid credentials, 403 for an inactive
            account, or 423 for a temporarily locked account.
    """
    try:
        user = service.login(request)
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        ) from exc
    except AccountLockedError as exc:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked",
        ) from exc
    except InactiveAccountError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        ) from exc

    settings = get_settings()
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    set_auth_cookies(
        response,
        access_token=access_token,
        refresh_token=refresh_token,
        settings=settings,
    )
    return user


@router.post(
    "/refresh",
    response_model=AuthenticatedUserResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Invalid or expired refresh token"},
    },
    summary="Refresh the access token",
)
def refresh(
    request: Request,
    response: Response,
    service: AuthService = Depends(get_auth_service),
) -> AuthenticatedUserResponse:
    """Issue a new access token from a valid refresh token cookie.

    The refresh token is read exclusively from the HttpOnly cookie. If the
    token is valid and the user still exists and is active, a new access token
    is set as an HttpOnly cookie and the safe user profile is returned. The
    refresh-token cookie is never modified.

    Args:
        request: The incoming request carrying the refresh-token cookie.
        response: The response the new access-token cookie is attached to.
        service: AuthService providing user lookup for token refresh.

    Returns:
        The safe authenticated-user profile; the new access token travels
        only in Set-Cookie.

    Raises:
        HTTPException: 401 for missing, invalid, expired, or wrong-type
            refresh tokens, or for inactive or nonexistent users.
    """
    refresh_token_value = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if refresh_token_value is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    try:
        claims = validate_refresh_token(refresh_token_value)
    except (InvalidTokenError, ExpiredTokenError, InvalidTokenTypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        ) from exc

    try:
        user = service.get_user_for_refresh(claims.user_id)
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        ) from exc

    settings = get_settings()
    new_access_token = create_access_token(user.id)
    set_access_token_cookie(
        response,
        access_token=new_access_token,
        settings=settings,
    )
    return AuthenticatedUserResponse.model_validate(user)
