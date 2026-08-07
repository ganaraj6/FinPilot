"""Aggregated module routers mounted on the FastAPI application."""

from fastapi import APIRouter

from app.modules.ai.router import router as ai_router
from app.modules.auth.router import router as auth_router
from app.modules.budgets.router import router as budgets_router
from app.modules.dashboard.router import router as dashboard_router
from app.modules.expenses.router import router as expenses_router
from app.modules.goals.router import router as goals_router
from app.modules.health_score.router import router as health_score_router
from app.modules.money.router import router as money_router
from app.modules.notifications.router import router as notifications_router
from app.modules.reports.router import router as reports_router
from app.modules.settings.router import router as settings_router

api_routers: list[APIRouter] = [
    ai_router,
    auth_router,
    budgets_router,
    dashboard_router,
    expenses_router,
    goals_router,
    health_score_router,
    money_router,
    notifications_router,
    reports_router,
    settings_router,
]
