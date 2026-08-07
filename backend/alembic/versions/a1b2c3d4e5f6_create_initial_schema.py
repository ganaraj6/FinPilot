"""create initial schema

Revision ID: a1b2c3d4e5f6
Revises:
Create Date: 2026-08-07

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply the migration changes."""
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("full_name", sa.String(length=120), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("profile_photo_url", sa.String(length=500), nullable=True),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("timezone", sa.String(length=50), nullable=False),
        sa.Column("onboarding_completed", sa.Boolean(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )

    op.create_table(
        "money_received",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("amount", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("amount >= 0", name=op.f("ck_money_received_amount_non_negative")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_money_received_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_money_received")),
    )
    op.create_index(
        op.f("ix_money_received_user_received_at"),
        "money_received",
        ["user_id", "received_at"],
        unique=False,
    )

    op.create_table(
        "expenses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("amount", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("spent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("amount > 0", name=op.f("ck_expenses_amount_positive")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_expenses_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_expenses")),
    )
    op.create_index(op.f("ix_expenses_category"), "expenses", ["category"], unique=False)
    op.create_index(op.f("ix_expenses_user_spent_at"), "expenses", ["user_id", "spent_at"], unique=False)

    op.create_table(
        "budgets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("amount_limit", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("period", sa.String(length=20), nullable=False),
        sa.Column("starts_on", sa.Date(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("amount_limit >= 0", name=op.f("ck_budgets_amount_limit_non_negative")),
        sa.CheckConstraint("period IN ('weekly', 'monthly', 'yearly')", name=op.f("ck_budgets_period_valid")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_budgets_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_budgets")),
        sa.UniqueConstraint("user_id", "category", "period", name=op.f("uq_budgets_user_category_period")),
    )
    op.create_index(op.f("ix_budgets_user_id"), "budgets", ["user_id"], unique=False)

    op.create_table(
        "goals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("target_amount", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("current_amount", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("target_date", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("current_amount >= 0", name=op.f("ck_goals_current_amount_non_negative")),
        sa.CheckConstraint("status IN ('active', 'completed', 'paused', 'cancelled')", name=op.f("ck_goals_status_valid")),
        sa.CheckConstraint("target_amount > 0", name=op.f("ck_goals_target_amount_positive")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_goals_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_goals")),
    )
    op.create_index(op.f("ix_goals_status"), "goals", ["status"], unique=False)
    op.create_index(op.f("ix_goals_user_id"), "goals", ["user_id"], unique=False)

    op.create_table(
        "goal_contributions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("goal_id", sa.Uuid(), nullable=False),
        sa.Column("amount", sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("contributed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("amount > 0", name=op.f("ck_goal_contributions_amount_positive")),
        sa.ForeignKeyConstraint(
            ["goal_id"],
            ["goals.id"],
            name=op.f("fk_goal_contributions_goal_id_goals"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_goal_contributions")),
    )
    op.create_index(op.f("ix_goal_contributions_contributed_at"), "goal_contributions", ["contributed_at"], unique=False)
    op.create_index(op.f("ix_goal_contributions_goal_id"), "goal_contributions", ["goal_id"], unique=False)

    op.create_table(
        "notifications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("notification_type", sa.String(length=50), nullable=False),
        sa.Column("is_read", sa.Boolean(), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_notifications_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notifications")),
    )
    op.create_index(op.f("ix_notifications_user_is_read"), "notifications", ["user_id", "is_read"], unique=False)

    op.create_table(
        "health_score_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("score", sa.SmallInteger(), nullable=False),
        sa.Column("breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("score BETWEEN 0 AND 100", name=op.f("ck_health_score_snapshots_score_range")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_health_score_snapshots_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_health_score_snapshots")),
    )
    op.create_index(
        op.f("ix_health_score_snapshots_user_recorded_at"),
        "health_score_snapshots",
        ["user_id", "recorded_at"],
        unique=False,
    )

    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("report_type", sa.String(length=50), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=True),
        sa.Column("period_end", sa.Date(), nullable=True),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_reports_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reports")),
    )
    op.create_index(op.f("ix_reports_report_type"), "reports", ["report_type"], unique=False)
    op.create_index(op.f("ix_reports_user_generated_at"), "reports", ["user_id", "generated_at"], unique=False)

    op.create_table(
        "user_settings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("theme", sa.String(length=20), nullable=False),
        sa.Column("locale", sa.String(length=10), nullable=False),
        sa.Column("weekly_report_enabled", sa.Boolean(), nullable=False),
        sa.Column("email_notifications_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_settings_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_settings")),
        sa.UniqueConstraint("user_id", name=op.f("uq_user_settings_user_id")),
    )


def downgrade() -> None:
    """Revert the migration changes."""
    op.drop_table("user_settings")
    op.drop_table("reports")
    op.drop_table("health_score_snapshots")
    op.drop_table("notifications")
    op.drop_table("goal_contributions")
    op.drop_table("goals")
    op.drop_table("budgets")
    op.drop_table("expenses")
    op.drop_table("money_received")
    op.drop_table("users")
