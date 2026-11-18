"""
Router xác thực quản trị viên Dashboard (Phase 0B - Step 3.4.5, 3.4.6 & 3.4.7).
Cung cấp endpoints:
- POST /api/v1/admin/auth/login: Đăng nhập quản trị viên, xác thực PBKDF2 và phát hành JWT Access Token.
- GET /api/v1/admin/auth/me: Lấy thông tin tài khoản quản trị viên hiện đang đăng nhập qua Bearer JWT.
- POST /api/v1/admin/auth/change-password: Thay đổi mật khẩu cho quản trị viên đang đăng nhập qua Bearer JWT.
"""

import logging
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.admin_dependencies import (
    CurrentAdmin,
    get_admin_token_service,
    get_current_admin,
)
from app.core.config import settings
from app.database import get_db
from app.schemas.admin_auth import (
    AdminChangePasswordRequest,
    AdminChangePasswordResponse,
    AdminInfoResponse,
    AdminLoginRequest,
    AdminLoginResponse,
)
from app.services.admin_auth import AdminAuthService
from app.services.admin_token import AdminTokenService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/auth", tags=["Admin Authentication"])


@router.post(
    "/login",
    response_model=AdminLoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Đăng nhập Dashboard Admin và nhận JWT Access Token",
)
def login(
    payload: AdminLoginRequest,
    db: Session = Depends(get_db),
    token_service: AdminTokenService = Depends(get_admin_token_service),
) -> AdminLoginResponse:
    """
    Xác thực quản trị viên Dashboard thông qua username và mật khẩu băm PBKDF2.

    Luồng xử lý:
    1. Nhận thông tin đăng nhập AdminLoginRequest.
    2. Sử dụng AdminAuthService với Session CSDL được inject để xác thực tài khoản app_admins.
    3. Kiểm tra tính hợp lệ của mật khẩu và trạng thái kích hoạt tài khoản (is_active=True).
    4. Khi xác thực thành công, phát hành JWT Access Token qua AdminTokenService.
    5. Trả về AdminLoginResponse chứa access_token và DTO thông tin quản trị an toàn.

    Ghi chú bảo mật:
    - Tuyệt đối không ghi mật khẩu hoặc chuỗi JWT đầy đủ vào log hệ thống.
    - Không trả về password, password_hash hoặc JWT secret ra client.
    - Thời hạn sống của token (expires_in) phản ánh đúng cấu hình hệ thống (ACCESS_TOKEN_EXPIRE_MINUTES).
    """
    # 1. Khởi tạo AdminAuthService từ Session được tiêm
    auth_service = AdminAuthService(db=db)

    # 2. Xác thực thông tin đăng nhập của Admin (ném ValidationError, UnauthorizedError, hoặc ForbiddenError nếu thất bại)
    admin_result = auth_service.authenticate(
        username=payload.username,
        password=payload.password,
    )

    # 3. Phát hành JWT Access Token thông qua AdminTokenService (ném ServiceUnavailableError nếu thiếu secret)
    access_token = token_service.create_access_token(admin=admin_result)

    # 4. Tính toán thời hạn sống thực tế từ cấu hình hệ thống
    expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    logger.info(
        "Admin ID %d ('%s', role: %s) đã đăng nhập thành công qua API.",
        admin_result.id,
        admin_result.username,
        admin_result.role,
    )

    # 5. Trả về response an toàn theo chuẩn OAuth2 Bearer Token
    return AdminLoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in_seconds,
        admin=AdminInfoResponse(
            id=admin_result.id,
            username=admin_result.username,
            email=admin_result.email,
            role=admin_result.role,
            is_active=admin_result.is_active,
            created_at=admin_result.created_at,
        ),
    )


@router.get(
    "/me",
    response_model=AdminInfoResponse,
    status_code=status.HTTP_200_OK,
    summary="Lấy thông tin tài khoản Admin hiện đang đăng nhập",
)
def get_me(
    current_admin: CurrentAdmin = Depends(get_current_admin),
) -> AdminInfoResponse:
    """
    Trả về thông tin hồ sơ an toàn của quản trị viên hiện tại từ Bearer JWT.

    Yêu cầu kiến trúc:
    - Bắt buộc xác thực Bearer token thông qua dependency get_current_admin.
    - Không tự xác thực JWT lần thứ 2.
    - Không tạo database session hoặc engine mới.
    - Không truy vấn database lần thứ 2 trong endpoint handler; tái sử dụng CurrentAdmin đã nạp từ CSDL.
    - Vai trò role phản ánh giá trị hiện tại từ database, không sử dụng role claim cũ trong JWT.
    - Tuyệt đối không trả về password, password_hash hoặc JWT secret ra client.
    """
    return AdminInfoResponse(
        id=current_admin.id,
        username=current_admin.username,
        email=current_admin.email,
        role=current_admin.role,
        is_active=current_admin.is_active,
        created_at=current_admin.created_at,
    )


@router.post(
    "/change-password",
    response_model=AdminChangePasswordResponse,
    status_code=status.HTTP_200_OK,
    summary="Thay đổi mật khẩu cho quản trị viên đang đăng nhập",
)
def change_password(
    payload: AdminChangePasswordRequest,
    current_admin: CurrentAdmin = Depends(get_current_admin),
    db: Session = Depends(get_db, use_cache=False),
) -> AdminChangePasswordResponse:
    """
    Thay đổi mật khẩu cho tài khoản Dashboard Admin hiện đang đăng nhập qua Bearer JWT.

    Yêu cầu kiến trúc:
    - Bắt buộc xác thực Bearer token thông qua dependency get_current_admin.
    - Định danh quản trị viên (admin_id) được lấy trực tiếp từ current_admin.id, chống hoàn toàn nguy cơ IDOR.
    - Database Session ghi được tiêm riêng biệt qua Depends(get_db, use_cache=False) để bảo đảm Session
      chưa bị kích hoạt autobegin transaction bởi get_current_admin, tuân thủ chặt chẽ ranh giới giao dịch
      của transactional() trong Service Layer.
    - Logic nghiệp vụ kiểm tra mật khẩu hiện tại, chống timing attack, cấm tái sử dụng mật khẩu cũ
      và commit giao dịch được quản lý tập trung bên trong AdminAuthService.change_password().
    - Tuyệt đối không trả về password hoặc password_hash ra response.
    """
    auth_service = AdminAuthService(db=db)

    admin_result = auth_service.change_password(
        admin_id=current_admin.id,
        current_password=payload.current_password,
        new_password=payload.new_password,
    )

    logger.info(
        "Admin ID %d ('%s') đã đổi mật khẩu thành công qua API.",
        admin_result.id,
        admin_result.username,
    )

    return AdminChangePasswordResponse(
        message="Đổi mật khẩu thành công.",
        admin=AdminInfoResponse(
            id=admin_result.id,
            username=admin_result.username,
            email=admin_result.email,
            role=admin_result.role,
            is_active=admin_result.is_active,
            created_at=admin_result.created_at,
        ),
    )
