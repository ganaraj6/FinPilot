"""Base repository primitives shared across module repositories."""

from abc import ABC
from typing import Generic, TypeVar

from sqlalchemy.orm import Session

from app.database.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(ABC, Generic[ModelType]):
    """Abstract base repository bound to a database session."""

    def __init__(self, db: Session) -> None:
        """Initialize the repository with a database session."""
        self._db = db
