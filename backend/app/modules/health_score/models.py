"""SQLAlchemy models for the health_score module."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, SmallInteger
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class HealthScoreSnapshot(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A point-in-time financial health score for a user."""

    __tablename__ = "health_score_snapshots"
    __table_args__ = (
        CheckConstraint("score BETWEEN 0 AND 100", name="score_range"),
        Index("ix_health_score_snapshots_user_recorded_at", "user_id", "recorded_at"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped["User"] = relationship(back_populates="health_score_snapshots")
