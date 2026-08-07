"""SQLAlchemy models for the goals module."""

import uuid
from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import CheckConstraint, Date, DateTime, ForeignKey, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin


class Goal(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A savings target a user is working toward."""

    __tablename__ = "goals"
    __table_args__ = (
        CheckConstraint("target_amount > 0", name="target_amount_positive"),
        CheckConstraint("current_amount >= 0", name="current_amount_non_negative"),
        CheckConstraint(
            "status IN ('active', 'completed', 'paused', 'cancelled')",
            name="status_valid",
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    target_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    current_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), default=0, nullable=False)
    target_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active", index=True, nullable=False)

    user: Mapped["User"] = relationship(back_populates="goals")
    contributions: Mapped[list["GoalContribution"]] = relationship(
        back_populates="goal",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class GoalContribution(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single amount contributed toward a goal."""

    __tablename__ = "goal_contributions"
    __table_args__ = (
        CheckConstraint("amount > 0", name="amount_positive"),
    )

    goal_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("goals.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    contributed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
    )

    goal: Mapped["Goal"] = relationship(back_populates="contributions")
