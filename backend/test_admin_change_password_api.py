"""
Bộ kiểm thử đơn vị cho Admin Password Change Schema & Handler (Phase 0B - Step 3.4.7.2).
Kiểm tra tính đúng đắn của:
1. Pydantic Schemas (AdminChangePasswordRequest, AdminChangePasswordResponse).
2. Endpoint Handler change_password (xác thực CurrentAdmin, gọi service, trả DTO an toàn).
3. Cấu hình Dependency Injection: bắt buộc use_cache=False cho database session ghi.
4. Đăng ký Route trên FastAPI application instance và bảo toàn toàn bộ routes hiện hữu.

Kiểm thử độc lập với SQLite in-memory và Mocks, không kết nối MariaDB thật.
"""

from datetime import datetime, timezone
import inspect
import json
from pathlib import Path
import sys
from typing import Generator
from unittest.mock import MagicMock, patch

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import Depends, Request
from fastapi.params import Depends as DependsClass
from pydantic import ValidationError as PydanticValidationError
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.admin_dependencies import (
    CurrentAdmin,
    get_admin_token_service,
    get_current_admin,
)
from app.core.exception_handlers import business_exception_handler
from app.core.exceptions import (
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    ValidationError as BusinessValidationError,
)
from app.core.security import hash_password
from app.database import Base, get_db
from app.main import app
from app.models.application import AppAdmin
from app.routers.admin_auth import change_password as admin_change_password_handler
from app.schemas.admin_auth import (
    AdminChangePasswordRequest,
    AdminChangePasswordResponse,
    AdminInfoResponse,
)
from app.services.admin_auth import AdminAuthResult, AdminAuthService


def make_mock_request(path: str = "/api/v1/admin/auth/change-password", method: str = "POST") -> Request:
    """Tạo mock Request cho kiểm thử Exception Handler."""
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode("ascii"),
        "headers": [],
        "query_string": b"",
    }
    return Request(scope)


@pytest.fixture
def sqlite_db_session() -> Generator[Session, None, None]:
    """Tạo database SQLite in-memory cô lập cho từng test case."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    session = TestingSession()

    try:
        active_admin = AppAdmin(
            username="super_admin",
            password_hash=hash_password("CurrentSecurePass123!"),
            email="admin@enterprise.local",
            role="superadmin",
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(active_admin)
        session.commit()

        session._active_admin = active_admin
        yield session
    finally:
        session.close()


@pytest.fixture
def sample_current_admin(sqlite_db_session: Session) -> CurrentAdmin:
    """Fixture CurrentAdmin an toàn được inject từ get_current_admin."""
    admin = sqlite_db_session._active_admin
    return CurrentAdmin(
        id=admin.id,
        username=admin.username,
        email=admin.email,
        role=admin.role,
        is_active=admin.is_active,
        created_at=admin.created_at,
    )


# =============================================================================
# NHÓM 1: PYDANTIC SCHEMA UNIT TESTS
# =============================================================================

def test_01_schema_valid_request():
    """1. Schema hợp lệ: Tạo thành công AdminChangePasswordRequest với dữ liệu chuẩn."""
    req = AdminChangePasswordRequest(
        current_password="OldPassword123!",
        new_password="NewStrongPassword456!",
        confirm_password="NewStrongPassword456!",
    )
    assert req.current_password == "OldPassword123!"
    assert req.new_password == "NewStrongPassword456!"
    assert req.confirm_password == "NewStrongPassword456!"


def test_02_schema_preserves_password_whitespaces():
    """2. Schema bảo toàn nguyên vẹn khoảng trắng đầu/cuối của các trường mật khẩu."""
    req = AdminChangePasswordRequest(
        current_password="  Old Pass Space  ",
        new_password="  New Pass Space 123!  ",
        confirm_password="  New Pass Space 123!  ",
    )
    assert req.current_password == "  Old Pass Space  "
    assert req.new_password == "  New Pass Space 123!  "
    assert req.confirm_password == "  New Pass Space 123!  "


def test_03_schema_rejects_empty_current_password():
    """3. Schema từ chối khi current_password rỗng."""
    with pytest.raises(PydanticValidationError) as exc_info:
        AdminChangePasswordRequest(
            current_password="",
            new_password="ValidNewPass123!",
            confirm_password="ValidNewPass123!",
        )
    assert "current_password" in str(exc_info.value)


def test_04_schema_rejects_short_new_password():
    """4. Schema từ chối khi new_password có độ dài dưới 8 ký tự."""
    short_passwords = ["1234567", "short", "a"]
    for sp in short_passwords:
        with pytest.raises(PydanticValidationError) as exc_info:
            AdminChangePasswordRequest(
                current_password="CurrentValidPass123!",
                new_password=sp,
                confirm_password=sp,
            )
        assert "new_password" in str(exc_info.value)


def test_05_schema_rejects_overlong_new_password():
    """5. Schema từ chối khi new_password có độ dài vượt quá 128 ký tự."""
    overlong = "A" * 129
    with pytest.raises(PydanticValidationError) as exc_info:
        AdminChangePasswordRequest(
            current_password="CurrentValidPass123!",
            new_password=overlong,
            confirm_password=overlong,
        )
    assert "new_password" in str(exc_info.value)


def test_06_schema_rejects_mismatched_confirm_password():
    """6. Schema từ chối khi confirm_password không trùng khớp với new_password."""
    with pytest.raises(PydanticValidationError) as exc_info:
        AdminChangePasswordRequest(
            current_password="CurrentValidPass123!",
            new_password="ValidNewPass123!",
            confirm_password="DifferentConfirmPass456!",
        )
    assert "Mật khẩu xác nhận không khớp" in str(exc_info.value)


def test_07_schema_response_serialization_safe():
    """7. AdminChangePasswordResponse serialize an toàn, không chứa password hoặc hash."""
    admin_info = AdminInfoResponse(
        id=1,
        username="super_admin",
        email="admin@enterprise.local",
        role="superadmin",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    resp = AdminChangePasswordResponse(
        message="Đổi mật khẩu thành công.",
        admin=admin_info,
    )
    dumped = resp.model_dump()
    assert dumped["message"] == "Đổi mật khẩu thành công."
    assert dumped["admin"]["username"] == "super_admin"
    assert "password" not in dumped
    assert "password_hash" not in dumped
    assert "password" not in dumped["admin"]
    assert "password_hash" not in dumped["admin"]


# =============================================================================
# NHÓM 2: HANDLER UNIT TESTS
# =============================================================================

def test_08_handler_successful_password_change(
    sample_current_admin: CurrentAdmin,
    sqlite_db_session: Session,
):
    """8. Handler thực thi thành công: Gọi service đúng admin_id và trả về AdminChangePasswordResponse."""
    payload = AdminChangePasswordRequest(
        current_password="CurrentSecurePass123!",
        new_password="BrandNewPass456!",
        confirm_password="BrandNewPass456!",
    )

    response = admin_change_password_handler(
        payload=payload,
        current_admin=sample_current_admin,
        db=sqlite_db_session,
    )

    assert isinstance(response, AdminChangePasswordResponse)
    assert response.message == "Đổi mật khẩu thành công."
    assert response.admin.id == sample_current_admin.id
    assert response.admin.username == sample_current_admin.username
    assert response.admin.role == sample_current_admin.role
    assert response.admin.is_active is True


def test_09_handler_uses_current_admin_id_preventing_idor(
    sample_current_admin: CurrentAdmin,
    sqlite_db_session: Session,
):
    """9. Handler truyền chính xác admin_id từ current_admin.id vào Service (chống IDOR)."""
    payload = AdminChangePasswordRequest(
        current_password="CurrentSecurePass123!",
        new_password="BrandNewPass456!",
        confirm_password="BrandNewPass456!",
    )

    with patch.object(AdminAuthService, "change_password") as mock_change_password:
        mock_change_password.return_value = AdminAuthResult(
            id=sample_current_admin.id,
            username=sample_current_admin.username,
            email=sample_current_admin.email,
            role=sample_current_admin.role,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )

        admin_change_password_handler(
            payload=payload,
            current_admin=sample_current_admin,
            db=sqlite_db_session,
        )

        mock_change_password.assert_called_once_with(
            admin_id=sample_current_admin.id,
            current_password=payload.current_password,
            new_password=payload.new_password,
        )


def test_10_handler_propagates_password_reused_validation_error(
    sample_current_admin: CurrentAdmin,
    sqlite_db_session: Session,
):
    """10. Handler để exception PASSWORD_REUSED nổi lên và được exception handler xử lý thành HTTP 422."""
    payload = AdminChangePasswordRequest(
        current_password="CurrentSecurePass123!",
        new_password="CurrentSecurePass123!",
        confirm_password="CurrentSecurePass123!",
    )

    with pytest.raises(BusinessValidationError) as exc_info:
        admin_change_password_handler(
            payload=payload,
            current_admin=sample_current_admin,
            db=sqlite_db_session,
        )

    assert exc_info.value.code == "PASSWORD_REUSED"
    assert exc_info.value.http_status == 422

    # Kiểm tra xử lý qua Global Exception Handler
    req = make_mock_request()
    json_resp = business_exception_handler(req, exc_info.value)
    assert json_resp.status_code == 422
    body = json.loads(json_resp.body.decode())
    assert body["error"]["code"] == "PASSWORD_REUSED"


def test_11_handler_propagates_unauthorized_error_wrong_password(
    sample_current_admin: CurrentAdmin,
    sqlite_db_session: Session,
):
    """11. Handler để exception INVALID_CREDENTIALS nổi lên và được exception handler xử lý thành HTTP 401."""
    payload = AdminChangePasswordRequest(
        current_password="WrongCurrentPassword!",
        new_password="BrandNewPass456!",
        confirm_password="BrandNewPass456!",
    )

    with pytest.raises(UnauthorizedError) as exc_info:
        admin_change_password_handler(
            payload=payload,
            current_admin=sample_current_admin,
            db=sqlite_db_session,
        )

    assert exc_info.value.code == "INVALID_CREDENTIALS"
    assert exc_info.value.http_status == 401

    req = make_mock_request()
    json_resp = business_exception_handler(req, exc_info.value)
    assert json_resp.status_code == 401
    body = json.loads(json_resp.body.decode())
    assert body["error"]["code"] == "INVALID_CREDENTIALS"


def _get_all_app_routes(application):
    """Trích xuất danh sách tất cả (path, methods) của các route trong FastAPI application."""
    routes = []
    for r in application.routes:
        if hasattr(r, "path"):
            routes.append((r.path, getattr(r, "methods", set())))
        elif hasattr(r, "original_router"):
            for sub_r in r.original_router.routes:
                routes.append((sub_r.path, getattr(sub_r, "methods", set())))
    return routes


def test_12_handler_propagates_forbidden_error_account_inactive(
    sample_current_admin: CurrentAdmin,
    sqlite_db_session: Session,
):
    """12. Handler để exception ACCOUNT_INACTIVE nổi lên và được exception handler xử lý thành HTTP 403."""
    payload = AdminChangePasswordRequest(
        current_password="CurrentSecurePass123!",
        new_password="BrandNewPass456!",
        confirm_password="BrandNewPass456!",
    )

    # Đặt tài khoản thành inactive trong CSDL và commit để đóng transaction trước đó
    active_admin = sqlite_db_session._active_admin
    active_admin.is_active = False
    sqlite_db_session.commit()

    with pytest.raises(ForbiddenError) as exc_info:
        admin_change_password_handler(
            payload=payload,
            current_admin=sample_current_admin,
            db=sqlite_db_session,
        )

    assert exc_info.value.code == "ACCOUNT_INACTIVE"
    assert exc_info.value.http_status == 403

    req = make_mock_request()
    json_resp = business_exception_handler(req, exc_info.value)
    assert json_resp.status_code == 403
    body = json.loads(json_resp.body.decode())
    assert body["error"]["code"] == "ACCOUNT_INACTIVE"


def test_13_handler_propagates_not_found_error_admin_deleted(
    sample_current_admin: CurrentAdmin,
    sqlite_db_session: Session,
):
    """13. Handler để exception RESOURCE_NOT_FOUND nổi lên khi admin_id không tồn tại (HTTP 404)."""
    payload = AdminChangePasswordRequest(
        current_password="CurrentSecurePass123!",
        new_password="BrandNewPass456!",
        confirm_password="BrandNewPass456!",
    )

    ghost_admin = CurrentAdmin(
        id=99999,
        username="ghost_admin",
        email="ghost@enterprise.local",
        role="superadmin",
        is_active=True,
    )

    with pytest.raises(NotFoundError) as exc_info:
        admin_change_password_handler(
            payload=payload,
            current_admin=ghost_admin,
            db=sqlite_db_session,
        )

    assert exc_info.value.code == "RESOURCE_NOT_FOUND"
    assert exc_info.value.http_status == 404

    req = make_mock_request()
    json_resp = business_exception_handler(req, exc_info.value)
    assert json_resp.status_code == 404
    body = json.loads(json_resp.body.decode())
    assert body["error"]["code"] == "RESOURCE_NOT_FOUND"


# =============================================================================
# NHÓM 3: DEPENDENCY INJECTION & ARCHITECTURAL INVARIANT TESTS
# =============================================================================

def test_14_handler_dependency_use_cache_is_false():
    """
    14. BẮT BUỘC: Kiểm tra cấu hình Dependency Injection của handler change_password:
    - Tham số 'db' phải được cấu hình bằng Depends(get_db, use_cache=False).
    - Bảo đảm FastAPI không dùng lại Session đã autobegin từ get_current_admin.
    """
    sig = inspect.signature(admin_change_password_handler)
    assert "db" in sig.parameters, "Handler phải có tham số 'db'"

    db_param = sig.parameters["db"]
    assert isinstance(db_param.default, DependsClass), "Tham số 'db' phải có default là Depends"
    assert db_param.default.dependency is get_db, "Dependency của 'db' phải là hàm get_db"
    assert db_param.default.use_cache is False, "BẮT BUỘC use_cache=False để bảo đảm Session ghi độc lập"


def test_15_handler_dependency_uses_get_current_admin():
    """15. BẮT BUỘC: Kiểm tra tham số 'current_admin' sử dụng Depends(get_current_admin)."""
    sig = inspect.signature(admin_change_password_handler)
    assert "current_admin" in sig.parameters, "Handler phải có tham số 'current_admin'"

    admin_param = sig.parameters["current_admin"]
    assert isinstance(admin_param.default, DependsClass), "Tham số 'current_admin' phải có default là Depends"
    assert admin_param.default.dependency is get_current_admin, "Dependency phải là get_current_admin"


# =============================================================================
# NHÓM 4: ROUTE REGISTRATION TESTS
# =============================================================================

def test_16_change_password_route_registered_on_fastapi_app():
    """16. Endpoint POST /api/v1/admin/auth/change-password đã được đăng ký trên FastAPI application."""
    routes = _get_all_app_routes(app)
    routes_map = {path: methods for path, methods in routes}

    target_path = "/api/v1/admin/auth/change-password"
    assert target_path in routes_map, f"Đường dẫn {target_path} chưa được đăng ký trên FastAPI app"
    assert "POST" in routes_map[target_path], f"Đường dẫn {target_path} không hỗ trợ phương thức POST"


def test_17_all_existing_routes_preserved():
    """17. Toàn bộ các route hiện hữu được bảo toàn tuyệt đối, không bị ghi đè hoặc mất mát."""
    routes = _get_all_app_routes(app)
    routes_map = {path: methods for path, methods in routes}

    # Xác minh các endpoint quản trị hiện có
    assert "/api/v1/admin/auth/login" in routes_map
    assert "POST" in routes_map["/api/v1/admin/auth/login"]

    assert "/api/v1/admin/auth/me" in routes_map
    assert "GET" in routes_map["/api/v1/admin/auth/me"]

    # Xác minh các endpoint health hiện có
    assert "/health" in routes_map
    assert "GET" in routes_map["/health"]

    assert "/health/database" in routes_map
    assert "GET" in routes_map["/health/database"]

    # Xác minh endpoint PAP login
    assert "/auth/login" in routes_map
    assert "POST" in routes_map["/auth/login"]
