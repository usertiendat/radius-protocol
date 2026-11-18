"""
RBAC Foundation (Role-Based Access Control) cho Dashboard Quản trị (Phase 0B - Step 3.4.4).
Cung cấp định nghĩa vai trò chuẩn hóa và dependency phân quyền có thể tái sử dụng:
1. Định nghĩa tập vai trò hợp lệ: superadmin, it_admin, auditor.
2. Áp dụng nguyên tắc Deny-by-default: Mọi vai trò không xác định hoặc không được phép đều bị từ chối.
3. Reusable Dependency Factory: require_roles(*allowed_roles).
4. Sử dụng CurrentAdmin từ Step 3.4.3 làm nguồn thẩm quyền duy nhất (Role từ CSDL, không dùng JWT claim cũ).
5. Không tự xác thực JWT lần 2, không tạo Engine/Session, không truy vấn database lần 2.
6. Thao tác hoàn toàn độc lập với FreeRADIUS radcheck.
"""

from enum import Enum
import logging
from typing import Callable, FrozenSet, Set, Union

from fastapi import Depends

from app.core.admin_dependencies import CurrentAdmin, get_current_admin
from app.core.exceptions import ForbiddenError

logger = logging.getLogger(__name__)


class AdminRole(str, Enum):
    """
    Tập vai trò quản trị viên hợp lệ trong hệ thống Dashboard.
    Kế thừa str và Enum để tương thích tự nhiên với string so sánh.
    """
    SUPERADMIN = "superadmin"
    IT_ADMIN = "it_admin"
    AUDITOR = "auditor"


# Tập hợp các vai trò hợp lệ (immutable set phục vụ kiểm tra nhanh O(1))
VALID_ROLES: FrozenSet[str] = frozenset(role.value for role in AdminRole)


def is_valid_role(role: Union[str, AdminRole, None]) -> bool:
    """
    Kiểm tra một vai trò có hợp lệ trong hệ thống hay không.
    Áp dụng nguyên tắc deny-by-default: None, rỗng, hoặc role không xác định đều trả về False.
    """
    if role is None:
        return False
    role_str = role.value if isinstance(role, AdminRole) else str(role).strip()
    return role_str in VALID_ROLES


def require_roles(
    *allowed_roles: Union[str, AdminRole],
) -> Callable[[CurrentAdmin], CurrentAdmin]:
    """
    Dependency Factory tạo FastAPI Dependency kiểm tra quyền hạn dựa trên vai trò (RBAC).

    Args:
        *allowed_roles: Danh sách một hoặc nhiều vai trò được phép truy cập (AdminRole hoặc string).

    Returns:
        Callable[[CurrentAdmin], CurrentAdmin]: FastAPI Dependency nhận CurrentAdmin và trả về chính CurrentAdmin
        nếu vai trò hiện tại hợp lệ và được cấp phép.

    Raises:
        ValueError: Khi cấu hình danh sách allowed_roles rỗng hoặc chứa vai trò không xác định trong hệ thống.
        ForbiddenError: Khi CurrentAdmin sở hữu vai trò không được phép hoặc vai trò không hợp lệ (HTTP 403, FORBIDDEN).
    """
    # 1. Kiểm tra cấu hình: Không cho phép danh sách vai trò cho phép bị rỗng
    if not allowed_roles:
        raise ValueError(
            "Cấu hình RBAC không hợp lệ: Danh sách 'allowed_roles' không được để trống. "
            "Phải chỉ định ít nhất một vai trò hợp lệ."
        )

    # 2. Chuẩn hóa và xác thực từng vai trò được cấu hình
    normalized_allowed: Set[str] = set()
    for role in allowed_roles:
        role_str = role.value if isinstance(role, AdminRole) else str(role).strip()
        if not is_valid_role(role_str):
            raise ValueError(
                f"Cấu hình RBAC không hợp lệ: Vai trò '{role}' không tồn tại trong hệ thống. "
                f"Các vai trò được hỗ trợ: {sorted(list(VALID_ROLES))}"
            )
        normalized_allowed.add(role_str)

    # 3. Tạo dependency kiểm tra quyền hạn thực thi tại thời điểm nhận HTTP Request
    def role_checker(
        current_admin: CurrentAdmin = Depends(get_current_admin),
    ) -> CurrentAdmin:
        """
        FastAPI Dependency xác thực quyền hạn của CurrentAdmin.
        Sử dụng role hiện tại trong CSDL từ CurrentAdmin, KHÔNG dựa vào role claim cũ trong JWT.
        """
        # A. Kiểm tra tính hợp lệ của vai trò hiện tại trong CurrentAdmin (Deny-by-default)
        if not current_admin.role or not is_valid_role(current_admin.role):
            logger.warning(
                "RBAC từ chối truy cập: Admin ID %s ('%s') sở hữu vai trò không hợp lệ hoặc rỗng: '%s'.",
                current_admin.id,
                current_admin.username,
                current_admin.role,
            )
            raise ForbiddenError(
                message="Tài khoản quản trị sở hữu vai trò không hợp lệ trong hệ thống.",
                code="FORBIDDEN",
            )

        admin_role_clean = (
            current_admin.role.value
            if isinstance(current_admin.role, AdminRole)
            else str(current_admin.role).strip()
        )

        # B. Kiểm tra vai trò của Admin có nằm trong danh sách được cấp phép không
        if admin_role_clean not in normalized_allowed:
            logger.warning(
                "RBAC từ chối truy cập: Admin ID %s ('%s') có vai trò '%s' không nằm trong danh sách cho phép %s.",
                current_admin.id,
                current_admin.username,
                admin_role_clean,
                sorted(list(normalized_allowed)),
            )
            raise ForbiddenError(
                message="Tài khoản không đủ quyền hạn để thực hiện thao tác này.",
                code="FORBIDDEN",
            )

        # C. Quyền hạn hợp lệ: Trả về đối tượng CurrentAdmin phục vụ cho router xử lý nghiệp vụ tiếp theo
        return current_admin

    return role_checker
