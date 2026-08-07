"""Database engine and session factory."""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config.settings import get_settings

_engine = create_engine(get_settings().database_url, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    """Yield a database session and guarantee it is always closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
