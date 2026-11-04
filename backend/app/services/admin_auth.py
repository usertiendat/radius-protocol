"""
Admin Authentication Service cho Dashboard Quản trị (Phase 0B - Step 3.4.1).
Chịu trách nhiệm:
1. Xác thực tài khoản Dashboard Admin thông qua SQLAlchemy ORM model AppAdmin.
2. Sử dụng cơ chế băm mật khẩu PBKDF2-HMAC-SHA256 (310.000 vòng) từ core/security.py.
3. Tách biệt hoàn toàn với xác thực người dùng mạng RADIUS (không sử dụng bảng radcheck).
4. Áp dụng chuẩn bảo mật:
   - Trả về thông tin Admin an toàn (không chứa password hay password_hash).
   - Thao tác chỉ đọc (Read-Only query), không tự commit/rollback.
   - Chống tấn công timing attack / username enumeration bằng dummy password verification.
   - Thống nhất thông điệp lỗi cho cả trường hợp sai username và sai password.
"""

from dataclasses import dataclass
from datetime import datetime
import logging
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from app.core.exceptions import ForbiddenError, UnauthorizedError, ValidationError
from app.core.security import verify_password
from app.models.application import AppAdmin
from app.services.base import BaseService

logger = logging.getLogger(__name__)

# Chuỗi băm giả lập định dạng chuẩn PBKDF2 dùng để ngăn chặn tấn công timing attack
# khi tên đăng nhập không tồn tại, bảo đảm thời gian phản hồi đồng nhất
DUMMY_PASSWORD_HASH = (
    "pbkdf2_sha256$310000$"
    "00000000000000000000000000000000$"
    "0000000000000000000000000000000000000000000000000000000000000000"
)


@dataclass(frozen=True)
class AdminAuthResult:
    """
    DTO đại diện cho thông tin tài khoản Admin sau khi xác thực thành công.
    Tuyệt đối không chứa trường 'password' hay 'password_hash'.
    """

    id: int
    username: str
    email: Optional[str]
    role: str
    is_active: bool
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Chuyển đổi thành từ điển an toàn."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __getitem__(self, item: str) -> Any:
        """Hỗ trợ truy xuất dạng dictionary-like an toàn."""
        if item in ("password", "password_hash"):
            raise KeyError(f"Trường nhạy cảm '{item}' không tồn tại trong AdminAuthResult")
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def __contains__(self, item: object) -> bool:
        """Kiểm tra sự tồn tại của trường trong DTO."""
        if item in ("password", "password_hash"):
            return False
        return hasattr(self, str(item))


class AdminAuthService(BaseService):
    """
    Dịch vụ xác thực danh tính cho quản trị viên Dashboard (AppAdmin).
    Kế thừa BaseService và tuân thủ chặt chẽ Service Layer Contract.
    """

    def authenticate(self, username: str, password: str) -> AdminAuthResult:
        """
        Xác thực tài khoản quản trị viên Dashboard.

        Args:
            username: Tên đăng nhập của quản trị viên.
            password: Mật khẩu dạng rõ của quản trị viên.

        Returns:
            AdminAuthResult: Thông tin quản trị viên an toàn.

        Raises:
            ValidationError: Khi username hoặc password rỗng/sai kiểu dữ liệu (HTTP 422).
            UnauthorizedError: Khi username không tồn tại hoặc sai mật khẩu (HTTP 401).
            ForbiddenError: Khi tài khoản bị vô hiệu hóa is_active=False (HTTP 403).
        """
        # 1. Validation kiểm tra tính hợp lệ của tham số đầu vào
        if not isinstance(username, str) or not username.strip():
            raise ValidationError(
                message="Tên đăng nhập không được để trống và phải là chuỗi ký tự.",
                code="VALIDATION_ERROR",
            )

        if not isinstance(password, str) or not password:
            raise ValidationError(
                message="Mật khẩu không được để trống và phải là chuỗi ký tự.",
                code="VALIDATION_ERROR",
            )

        username_clean = username.strip()

        # 2. Truy vấn AppAdmin từ CSDL bằng SQLAlchemy Session được inject
        admin: Optional[AppAdmin] = (
            self.db.query(AppAdmin)
            .filter(AppAdmin.username == username_clean)
            .first()
        )

        # 3. Xử lý khi username không tồn tại (Chống Timing Attack / User Enumeration)
        if admin is None:
            # Chạy hàm verify_password với hash giả lập cùng số vòng lặp 310.000 để giữ thời gian thực thi ngang nhau
            verify_password(password, DUMMY_PASSWORD_HASH)
            logger.warning(
                "Đăng nhập Dashboard Admin thất bại: Tên đăng nhập '%s' không tồn tại.",
                username_clean,
            )
            # Không tiết lộ cho client biết username không tồn tại
            raise UnauthorizedError(
                message="Tên đăng nhập hoặc mật khẩu không chính xác.",
                code="INVALID_CREDENTIALS",
            )

        # 4. Xác minh mật khẩu với chuỗi băm PBKDF2 của tài khoản
        is_password_valid = verify_password(password, admin.password_hash)
        if not is_password_valid:
            logger.warning(
                "Đăng nhập Dashboard Admin thất bại: Mật khẩu không chính xác cho tài khoản '%s'.",
                username_clean,
            )
            # Thống nhất loại lỗi và thông điệp giống hệt trường hợp không tìm thấy username
            raise UnauthorizedError(
                message="Tên đăng nhập hoặc mật khẩu không chính xác.",
                code="INVALID_CREDENTIALS",
            )

        # 5. Kiểm tra trạng thái kích hoạt của tài khoản
        if not admin.is_active:
            logger.warning(
                "Đăng nhập Dashboard Admin bị từ chối: Tài khoản '%s' đã bị vô hiệu hóa (is_active=False).",
                username_clean,
            )
            raise ForbiddenError(
                message="Tài khoản quản trị đã bị vô hiệu hóa. Vui lòng liên hệ quản trị viên cấp cao.",
                code="ACCOUNT_INACTIVE",
            )

        # 6. Xác thực thành công: Trả về đối tượng Admin an toàn
        logger.info(
            "Dashboard Admin '%s' (role: %s) đã xác thực thành công.",
            admin.username,
            admin.role,
        )

        return AdminAuthResult(
            id=admin.id,
            username=admin.username,
            email=admin.email,
            role=admin.role,
            is_active=admin.is_active,
            created_at=admin.created_at,
        )
