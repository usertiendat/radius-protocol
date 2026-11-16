"""
Package routers chứa các API Routers của FastAPI application.
"""

from app.routers.admin_auth import router as admin_auth_router
from app.routers.health import router as health_router

__all__ = [
    "health_router",
    "admin_auth_router",
]
