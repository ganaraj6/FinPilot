"""SQLAlchemy models for the settings module."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.modules.auth.models import User


class UserSettings(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One-to-one user preferences for the FinPilot application."""

    __tablename__ = "user_settings"
    __table_args__ = (UniqueConstraint("user_id", name="user_id"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    theme: Mapped[str] = mapped_column(String(20), default="system", nullable=False)
    locale: Mapped[str] = mapped_column(String(10), default="en-US", nullable=False)
    weekly_report_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    email_notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    user: Mapped[User] = relationship(back_populates="user_settings")
