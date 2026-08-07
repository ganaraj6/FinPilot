"""SQLAlchemy models for the auth module."""

import uuid

from sqlalchemy import Boolean, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin


class User(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A registered user of the FinPilot platform."""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", name="email"),)

    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    profile_photo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    currency: Mapped[str] = mapped_column(String(3), default="USD", nullable=False)
    timezone: Mapped[str] = mapped_column(String(50), default="UTC", nullable=False)
    onboarding_completed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    expenses: Mapped[list["Expense"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    money_received: Mapped[list["MoneyReceived"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    budgets: Mapped[list["Budget"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    goals: Mapped[list["Goal"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    notifications: Mapped[list["Notification"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    health_score_snapshots: Mapped[list["HealthScoreSnapshot"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    user_settings: Mapped["UserSettings | None"] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )
