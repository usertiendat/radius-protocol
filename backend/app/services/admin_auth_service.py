"""Business logic for application administrator authentication."""

from app.core.exceptions import UnauthorizedError
from app.core.security import create_access_token, verify_password
from app.models.application import AppAdmin
from app.services.base import BaseService


class AdminAuthService(BaseService):
    def authenticate(self, username: str, password: str) -> tuple[AppAdmin, str]:
        admin = (
            self.db.query(AppAdmin)
            .filter(AppAdmin.username == username)
            .one_or_none()
        )
        if (
            admin is None
            or not admin.is_active
            or not verify_password(password, admin.password_hash)
        ):
            raise UnauthorizedError("Tên đăng nhập hoặc mật khẩu Admin không hợp lệ.")

        token = create_access_token(
            {"sub": admin.username, "role": admin.role, "token_type": "admin"}
        )
        return admin, token

    def get_active_admin(self, username: str) -> AppAdmin:
        admin = (
            self.db.query(AppAdmin)
            .filter(AppAdmin.username == username, AppAdmin.is_active.is_(True))
            .one_or_none()
        )
        if admin is None:
            raise UnauthorizedError("Tài khoản Admin không còn quyền truy cập.")
        return admin
