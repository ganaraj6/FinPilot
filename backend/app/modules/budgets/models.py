"""SQLAlchemy models for the budgets module."""

from __future__ import annotations

import uuid
from datetime import date
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, Date, ForeignKey, Numeric, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.modules.auth.models import User


class Budget(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A spending limit configured by a user for a category and period."""

    __tablename__ = "budgets"
    __table_args__ = (
        CheckConstraint("amount_limit >= 0", name="amount_limit_non_negative"),
        CheckConstraint(
            "period IN ('weekly', 'monthly', 'yearly')",
            name="period_valid",
        ),
        UniqueConstraint("user_id", "category", "period", name="user_category_period"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    amount_limit: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    period: Mapped[str] = mapped_column(String(20), default="monthly", nullable=False)
    starts_on: Mapped[date | None] = mapped_column(Date, nullable=True)

    user: Mapped[User] = relationship(back_populates="budgets")
