"""
Admin Dependencies cho FastAPI Backend (Phase 0B - Step 3.4.3).
Cung cấp dependency get_current_admin xác định danh tính Dashboard Admin từ JWT Bearer Token:
1. Trích xuất Bearer Token từ Authorization Header thông qua FastAPI HTTPBearer.
2. Từ chối yêu cầu thiếu header, sai scheme (Basic, ...), hoặc token rỗng/malformed.
3. Xác minh JWT Access Token bằng AdminTokenService (HS256, 30 phút, claims sub/role/type).
4. Truy vấn AppAdmin từ CSDL bằng SQLAlchemy Session được inject qua get_db.
5. Kiểm tra tài khoản tồn tại trong bảng app_admins và trạng thái is_active=True.
6. Trả về DTO CurrentAdmin an toàn (tuyệt đối không chứa password hay password_hash).
7. Hoàn toàn độc lập với bảng radcheck của FreeRADIUS.
8. Thao tác chỉ đọc (Read-Only query), không tự mở Engine/Session, không gọi commit/rollback.
"""

from dataclasses import dataclass
import logging
from typing import Optional

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.database import get_db
from app.models.application import AppAdmin
from app.services.admin_auth import AdminAuthResult
from app.services.admin_token import AdminTokenClaims, AdminTokenService

logger = logging.getLogger(__name__)

# Khởi tạo HTTPBearer bảo mật với auto_error=False để kiểm soát ngoại lệ tập trung
# và đồng nhất với Global Exception Handlers (ngăn chặn lỗi 403 mặc định của FastAPI)
oauth2_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentAdmin(AdminAuthResult):
    """
    DTO đại diện cho thông tin tài khoản Dashboard Admin hiện tại đã được xác thực an toàn.
    Kế thừa AdminAuthResult để bảo đảm tính nhất quán và ngăn chặn hoàn toàn việc rò rỉ password.
    """
    pass


def get_admin_token_service() -> AdminTokenService:
    """Dependency cung cấp instance của AdminTokenService (hỗ trợ override dễ dàng trong test)."""
    return AdminTokenService()


def get_current_admin(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_bearer_scheme),
    db: Session = Depends(get_db),
    token_service: AdminTokenService = Depends(get_admin_token_service),
) -> CurrentAdmin:
    """
    FastAPI Dependency: Xác thực và trả về thông tin Admin hiện tại từ JWT Bearer Token.

    Luồng xử lý:
    1. Kiểm tra sự tồn tại và tính hợp lệ của Authorization header (Bearer scheme).
    2. Xác minh chữ ký số, thời hạn (exp), và claims bắt buộc qua AdminTokenService.
    3. Trích xuất định danh duy nhất (sub) và chuyển đổi sang integer ID.
    4. Truy vấn AppAdmin trong CSDL bằng session db được inject.
    5. Kiểm tra tài khoản tồn tại và trạng thái kích hoạt (is_active=True).
    6. Trả về DTO an toàn CurrentAdmin.

    Raises:
        UnauthorizedError: Khi thiếu token, sai scheme, token hết hạn/không hợp lệ, hoặc admin không tồn tại (HTTP 401).
        ForbiddenError: Khi tài khoản quản trị bị vô hiệu hóa is_active=False (HTTP 403, code ACCOUNT_INACTIVE).
    """
    # 1. Trích xuất Authorization header từ request nếu có
    auth_header: Optional[str] = None
    if request is not None and hasattr(request, "headers"):
        auth_header = request.headers.get("Authorization") or request.headers.get("authorization")

    # 2. Kiểm tra sự tồn tại của Authorization header
    if auth_header is None and credentials is None:
        logger.warning("Truy cập yêu cầu xác thực thất bại: Thiếu Authorization header.")
        raise UnauthorizedError(
            message="Yêu cầu cung cấp Authorization Header với Bearer token.",
            code="UNAUTHORIZED",
        )

    # 3. Kiểm tra tính hợp lệ của Scheme (bắt buộc phải là Bearer)
    if auth_header is not None:
        parts = auth_header.strip().split()
        if not parts:
            logger.warning("Truy cập thất bại: Authorization header rỗng.")
            raise UnauthorizedError(
                message="Authorization header không được để trống.",
                code="TOKEN_INVALID",
            )
        scheme = parts[0]
        if scheme.lower() != "bearer":
            logger.warning(
                "Truy cập thất bại: Scheme xác thực không hợp lệ (nhận '%s', yêu cầu 'Bearer').",
                scheme,
            )
            raise UnauthorizedError(
                message="Phương thức xác thực không hợp lệ. Yêu cầu Bearer token.",
                code="TOKEN_INVALID",
            )
        if len(parts) == 1:
            logger.warning("Truy cập thất bại: Header có Bearer scheme nhưng thiếu chuỗi token.")
            raise UnauthorizedError(
                message="Token truy cập không được để trống.",
                code="TOKEN_INVALID",
            )

    # 4. Trích xuất chuỗi token thô (raw token)
    raw_token: Optional[str] = None
    if credentials is not None and credentials.credentials:
        raw_token = credentials.credentials
    elif auth_header is not None:
        parts = auth_header.strip().split(maxsplit=1)
        if len(parts) > 1:
            raw_token = parts[1]

    if not raw_token or not raw_token.strip():
        logger.warning("Truy cập thất bại: Chuỗi token truy cập rỗng.")
        raise UnauthorizedError(
            message="Token truy cập không được để trống.",
            code="TOKEN_INVALID",
        )

    clean_token = raw_token.strip()

    # 5. Xác minh JWT Access Token bằng AdminTokenService
    claims: AdminTokenClaims = token_service.verify_access_token(clean_token)

    # 6. Kiểm tra và chuyển đổi Admin ID từ claim 'sub' sang kiểu int (khóa chính của AppAdmin)
    try:
        admin_id = int(claims.sub)
    except (ValueError, TypeError):
        logger.warning(
            "Truy cập thất bại: Claim 'sub' ('%s') không thể chuyển đổi thành số nguyên ID.",
            claims.sub,
        )
        raise UnauthorizedError(
            message="Token truy cập chứa định danh quản trị viên không hợp lệ.",
            code="TOKEN_INVALID",
        )

    # 7. Truy vấn AppAdmin trong CSDL bằng Session được inject
    admin: Optional[AppAdmin] = (
        db.query(AppAdmin)
        .filter(AppAdmin.id == admin_id)
        .first()
    )

    # 8. Kiểm tra sự tồn tại của Admin trong hệ thống
    if admin is None:
        logger.warning(
            "Truy cập thất bại: Không tìm thấy quản trị viên tương ứng với Admin ID %d.",
            admin_id,
        )
        raise UnauthorizedError(
            message="Tài khoản quản trị viên không tồn tại hoặc đã bị xóa.",
            code="TOKEN_INVALID",
        )

    # 9. Kiểm tra trạng thái kích hoạt của tài khoản
    if not admin.is_active:
        logger.warning(
            "Truy cập thất bại: Tài khoản quản trị viên ID %d ('%s') đã bị vô hiệu hóa.",
            admin.id,
            admin.username,
        )
        raise ForbiddenError(
            message="Tài khoản quản trị đã bị vô hiệu hóa. Vui lòng liên hệ quản trị viên cấp cao.",
            code="ACCOUNT_INACTIVE",
        )

    # 10. Trả về DTO thông tin Admin an toàn
    return CurrentAdmin(
        id=admin.id,
        username=admin.username,
        email=admin.email,
        role=admin.role,
        is_active=admin.is_active,
        created_at=admin.created_at,
    )
