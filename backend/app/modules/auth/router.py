"""HTTP router for the auth module.

The router is intentionally thin: it validates HTTP input, builds the auth
service from the existing database session dependency, delegates business logic
to AuthService, and translates known domain exceptions into HTTP responses.
No business logic (email normalization, password hashing, duplicate detection)
lives here.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.exceptions import EmailAlreadyRegisteredError
from app.database.session import get_db
from app.modules.auth.repository import UserRepository
from app.modules.auth.schemas import AuthenticatedUserResponse, UserRegistrationRequest
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
