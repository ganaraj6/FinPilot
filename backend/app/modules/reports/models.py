"""SQLAlchemy models for the reports module."""

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import Date, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Report(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A generated financial report for a user over a date range."""

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_user_generated_at", "user_id", "generated_at"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    report_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    period_start: Mapped[date | None] = mapped_column(Date, nullable=True)
    period_end: Mapped[date | None] = mapped_column(Date, nullable=True)
    data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped["User"] = relationship(back_populates="reports")
