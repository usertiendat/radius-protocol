"""
Core configuration and security package for RADIUS Management Backend.
"""

from app.core.admin_dependencies import (
    CurrentAdmin,
    get_admin_token_service,
    get_current_admin,
)
from app.core.rbac import (
    AdminRole,
    VALID_ROLES,
    is_valid_role,
    require_roles,
)

__all__ = [
    "CurrentAdmin",
    "get_current_admin",
    "get_admin_token_service",
    "AdminRole",
    "VALID_ROLES",
    "is_valid_role",
    "require_roles",
]
