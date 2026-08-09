"""SQLAlchemy models for the auth module."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.modules.budgets.models import Budget
    from app.modules.expenses.models import Expense
    from app.modules.goals.models import Goal
    from app.modules.health_score.models import HealthScoreSnapshot
    from app.modules.money.models import MoneyReceived
    from app.modules.notifications.models import Notification
    from app.modules.reports.models import Report
    from app.modules.settings.models import UserSettings


class User(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A registered user of the FinPilot platform."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", name="email"),)

    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    # Emails are normalized to lowercase at the application layer: the auth
    # service stores emails lowercased and performs authentication lookups
    # with lowercase emails. Normalization will occur in the auth service
    # (app/modules/auth/service.py), not in PostgreSQL (no CITEXT, no
    # lowercase index). The existing unique constraint is kept as-is.
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    profile_photo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    currency: Mapped[str] = mapped_column(String(3), default="USD", nullable=False)
    timezone: Mapped[str] = mapped_column(String(50), default="UTC", nullable=False)
    onboarding_completed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    expenses: Mapped[list[Expense]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    money_received: Mapped[list[MoneyReceived]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    budgets: Mapped[list[Budget]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    goals: Mapped[list[Goal]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    notifications: Mapped[list[Notification]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    health_score_snapshots: Mapped[list[HealthScoreSnapshot]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    user_settings: Mapped[UserSettings | None] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )
