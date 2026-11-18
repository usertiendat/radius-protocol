"""
Core configuration and security package for RADIUS Management Backend.
"""

def __getattr__(name: str):
    if name in ("CurrentAdmin", "get_admin_token_service", "get_current_admin"):
        from app.core import admin_dependencies
        return getattr(admin_dependencies, name)
    if name in ("AdminRole", "VALID_ROLES", "is_valid_role", "require_roles"):
        from app.core import rbac
        return getattr(rbac, name)
    raise AttributeError(f"module 'app.core' has no attribute '{name}'")

__all__ = [
    "CurrentAdmin",
    "get_current_admin",
    "get_admin_token_service",
    "AdminRole",
    "VALID_ROLES",
    "is_valid_role",
    "require_roles",
]
