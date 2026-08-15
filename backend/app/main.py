"""FastAPI application entrypoint."""

from fastapi import FastAPI

from app.config.settings import get_settings
from app.routers import api_routers

settings = get_settings()

app = FastAPI(title=settings.app_name, version=settings.app_version)

for router in api_routers:
    app.include_router(router, prefix=settings.api_v1_prefix)
