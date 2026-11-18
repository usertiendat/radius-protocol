"""
Package routers chứa các API Routers của FastAPI application.
"""

from app.routers.accounting import router as accounting_router
from app.routers.admin_auth import router as admin_auth_router
from app.routers.groups import router as groups_router
from app.routers.health import router as health_router
from app.routers.users import router as users_router

__all__ = [
    "health_router",
    "admin_auth_router",
    "accounting_router",
    "users_router",
    "groups_router",
]
