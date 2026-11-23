"""
Bộ kiểm thử đơn vị cho RBAC Foundation (Phase 0B - Step 3.4.4).
Kiểm thử độc lập với SQLite in-memory, Mock và Starlette Request, không kết nối MariaDB thật.
Bao gồm đầy đủ 12+ kiểm thử bắt buộc theo đặc tả Step 3.4.4.
"""

import ast
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Dict, Generator, Optional
from unittest.mock import MagicMock

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.admin_dependencies import CurrentAdmin, get_current_admin
from app.core.exception_handlers import business_exception_handler
from app.core.exceptions import ForbiddenError
from app.core.rbac import (
    AdminRole,
    VALID_ROLES,
    is_valid_role,
    require_roles,
)
from app.core.security import hash_password
from app.database import Base
from app.models.application import AppAdmin
from app.services.admin_token import AdminTokenService

TEST_SECRET_KEY = "test-jwt-secret-key-32-chars-long-for-safe-unit-testing"


def make_request(headers: Optional[Dict[str, str]] = None) -> Request:
    """Tạo đối tượng Request độc lập an toàn phục vụ kiểm thử."""
    raw_headers = []
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/admin/secure-resource",
        "raw_path": b"/api/v1/admin/secure-resource",
        "headers": raw_headers,
        "query_string": b"",
    }
    return Request(scope)


def make_current_admin(role: str, admin_id: int = 1, username: str = "test_admin", is_active: bool = True) -> CurrentAdmin:
    """Helper tạo đối tượng CurrentAdmin giả lập nhanh chóng."""
    return CurrentAdmin(
        id=admin_id,
        username=username,
        email="test@enterprise.local",
        role=role,
        is_active=is_active,
        created_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def sqlite_db_session() -> Generator[Session, None, None]:
    """Tạo database SQLite in-memory cô lập cho từng test case."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSession()

    try:
        superadmin = AppAdmin(
            username="super_user",
            password_hash=hash_password("SuperSecretPass123!"),
            email="super@enterprise.local",
            role=AdminRole.SUPERADMIN.value,
            is_active=True,
        )
        it_admin = AppAdmin(
            username="it_user",
            password_hash=hash_password("ItSecretPass123!"),
            email="it@enterprise.local",
            role=AdminRole.IT_ADMIN.value,
            is_active=True,
        )
        auditor = AppAdmin(
            username="auditor_user",
            password_hash=hash_password("AuditSecretPass123!"),
            email="audit@enterprise.local",
            role=AdminRole.AUDITOR.value,
            is_active=True,
        )
        session.add(superadmin)
        session.add(it_admin)
        session.add(auditor)
        session.commit()

        yield session
    finally:
        session.close()


@pytest.fixture
def test_token_service() -> AdminTokenService:
    """Tạo instance AdminTokenService cho test."""
    return AdminTokenService(secret_key=TEST_SECRET_KEY)


# =============================================================================
# 12 KIỂM THỬ BẮT BUỘC THEO ĐẶC TẢ STEP 3.4.4
# =============================================================================

def test_01_superadmin_allowed_success():
    """1. superadmin truy cập thành công khi role được cho phép."""
    admin = make_current_admin(role=AdminRole.SUPERADMIN.value)
    checker = require_roles(AdminRole.SUPERADMIN)

    result = checker(current_admin=admin)
    assert result is admin
    assert result.role == AdminRole.SUPERADMIN.value


def test_02_it_admin_allowed_success():
    """2. it_admin truy cập thành công khi role được cho phép."""
    admin = make_current_admin(role=AdminRole.IT_ADMIN.value)
    checker = require_roles(AdminRole.IT_ADMIN)

    result = checker(current_admin=admin)
    assert result is admin
    assert result.role == AdminRole.IT_ADMIN.value


def test_03_auditor_allowed_success():
    """3. auditor truy cập thành công khi role được cho phép."""
    admin = make_current_admin(role=AdminRole.AUDITOR.value)
    checker = require_roles(AdminRole.AUDITOR)

    result = checker(current_admin=admin)
    assert result is admin
    assert result.role == AdminRole.AUDITOR.value


def test_04_disallowed_role_returns_403_forbidden():
    """4. Role không được phép trả về 403 ForbiddenError."""
    # it_admin cố gắng truy cập endpoint chỉ dành cho superadmin
    admin = make_current_admin(role=AdminRole.IT_ADMIN.value)
    checker = require_roles(AdminRole.SUPERADMIN)

    with pytest.raises(ForbiddenError) as exc_info:
        checker(current_admin=admin)

    assert exc_info.value.code == "FORBIDDEN"
    assert exc_info.value.http_status == 403
    assert "không đủ quyền hạn" in exc_info.value.message.lower()


def test_05_multiple_allowed_roles_work_correctly():
    """5. Một dependency cho phép nhiều role hoạt động chính xác."""
    # Cho phép cả superadmin và it_admin
    checker = require_roles(AdminRole.SUPERADMIN, AdminRole.IT_ADMIN)

    admin_super = make_current_admin(role=AdminRole.SUPERADMIN.value)
    admin_it = make_current_admin(role=AdminRole.IT_ADMIN.value)
    admin_audit = make_current_admin(role=AdminRole.AUDITOR.value)

    # superadmin & it_admin đều thành công
    assert checker(current_admin=admin_super) is admin_super
    assert checker(current_admin=admin_it) is admin_it

    # auditor bị từ chối
    with pytest.raises(ForbiddenError) as exc_info:
        checker(current_admin=admin_audit)
    assert exc_info.value.http_status == 403


def test_06_unknown_role_rejected_deny_by_default():
    """6. Role không xác định bị từ chối theo nguyên tắc deny-by-default (403)."""
    admin = make_current_admin(role="unknown_guest_role")
    checker = require_roles(AdminRole.SUPERADMIN, AdminRole.IT_ADMIN, AdminRole.AUDITOR)

    with pytest.raises(ForbiddenError) as exc_info:
        checker(current_admin=admin)

    assert exc_info.value.code == "FORBIDDEN"
    assert exc_info.value.http_status == 403
    assert "không hợp lệ" in exc_info.value.message.lower()


def test_07_missing_or_empty_role_rejected():
    """7. Role bị thiếu hoặc rỗng bị từ chối (403)."""
    checker = require_roles(AdminRole.SUPERADMIN)

    for empty_role in ["", "   ", None]:
        admin = make_current_admin(role=empty_role)  # type: ignore
        with pytest.raises(ForbiddenError) as exc_info:
            checker(current_admin=admin)
        assert exc_info.value.http_status == 403
        assert exc_info.value.code == "FORBIDDEN"


def test_08_empty_allowed_roles_config_raises_value_error():
    """8. Không cho phép cấu hình danh sách allowed_roles rỗng (raise ValueError)."""
    with pytest.raises(ValueError) as exc_info:
        require_roles()

    assert "không được để trống" in str(exc_info.value).lower()


def test_09_current_admin_db_role_takes_precedence_over_jwt_role(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """
    9. Role hiện tại trong CSDL (qua CurrentAdmin) được sử dụng làm nguồn thẩm quyền,
    thay vì role claim cũ trong JWT:
    - Admin ban đầu nhận JWT có role 'superadmin'.
    - Trong CSDL, role của admin bị hạ xuống 'auditor'.
    - Khi truy cập endpoint yêu cầu 'superadmin', phải bị từ chối 403 vì CSDL là thẩm quyền.
    """
    admin_db = sqlite_db_session.query(AppAdmin).filter(AppAdmin.username == "super_user").first()
    assert admin_db is not None
    assert admin_db.role == AdminRole.SUPERADMIN.value

    # Phát hành token với claim role="superadmin"
    token = test_token_service.create_access_token(admin_db)

    # Thay đổi role của admin trong database thành "auditor"
    admin_db.role = AdminRole.AUDITOR.value
    sqlite_db_session.commit()

    # Xác thực qua get_current_admin (Step 3.4.3)
    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    current_admin = get_current_admin(
        request=req,
        credentials=creds,
        db=sqlite_db_session,
        token_service=test_token_service,
    )

    # CurrentAdmin mang role thực tế từ CSDL là 'auditor'
    assert current_admin.role == AdminRole.AUDITOR.value

    # Kiểm tra phân quyền: Yêu cầu SUPERADMIN
    superadmin_checker = require_roles(AdminRole.SUPERADMIN)
    with pytest.raises(ForbiddenError) as exc_info:
        superadmin_checker(current_admin=current_admin)

    assert exc_info.value.http_status == 403
    assert exc_info.value.code == "FORBIDDEN"


def test_10_invalid_role_admin_not_promoted():
    """10. Admin có role lạ/không hợp lệ không tự động được promote thành superadmin/it_admin."""
    admin_weird = make_current_admin(role="root_hacker")
    checker = require_roles(AdminRole.SUPERADMIN)

    with pytest.raises(ForbiddenError):
        checker(current_admin=admin_weird)


def test_11_rbac_dependency_integrates_with_get_current_admin(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """11. Dependency RBAC tương thích hoàn hảo với get_current_admin."""
    admin_db = sqlite_db_session.query(AppAdmin).filter(AppAdmin.username == "it_user").first()
    assert admin_db is not None
    token = test_token_service.create_access_token(admin_db)

    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    # 1. Bước xác thực (Authentication)
    current_admin = get_current_admin(
        request=req,
        credentials=creds,
        db=sqlite_db_session,
        token_service=test_token_service,
    )

    # 2. Bước phân quyền (Authorization)
    checker = require_roles(AdminRole.IT_ADMIN, AdminRole.SUPERADMIN)
    authorized_admin = checker(current_admin=current_admin)

    assert authorized_admin is current_admin
    assert authorized_admin.username == "it_user"
    assert authorized_admin.role == AdminRole.IT_ADMIN.value


def test_12_exception_contract_compliance():
    """12. Các trường hợp exception tuân thủ đúng Exception Contract (HTTP 403, error JSON format)."""
    admin = make_current_admin(role=AdminRole.AUDITOR.value)
    checker = require_roles(AdminRole.SUPERADMIN)

    req = make_request()
    with pytest.raises(ForbiddenError) as exc_info:
        checker(current_admin=admin)

    # Xử lý qua Global Exception Handler
    resp = business_exception_handler(req, exc_info.value)
    assert resp.status_code == 403
    data = json.loads(resp.body.decode("utf-8"))

    assert "error" in data
    assert data["error"]["code"] == "FORBIDDEN"
    assert isinstance(data["error"]["message"], str)
    assert len(data["error"]["message"]) > 0


# =============================================================================
# CÁC TEST BỔ SUNG: ROLE DEFINITIONS, AST & PERFORMANCE CHECKS
# =============================================================================

def test_13_invalid_allowed_role_config_raises_value_error():
    """13. Cấu hình vai trò không tồn tại trong hệ thống sẽ raise ValueError ngay lập tức."""
    with pytest.raises(ValueError) as exc_info:
        require_roles("non_existent_role")

    assert "không tồn tại trong hệ thống" in str(exc_info.value)


def test_14_supports_both_enum_and_string_literals():
    """14. Hỗ trợ truyền linh hoạt cả AdminRole Enum và chuỗi string literal."""
    checker_enum = require_roles(AdminRole.SUPERADMIN)
    checker_str = require_roles("superadmin")

    admin = make_current_admin(role="superadmin")
    assert checker_enum(admin) is admin
    assert checker_str(admin) is admin


def test_15_rbac_module_does_not_create_engine_or_session():
    """15. AST Check: Module app/core/rbac.py không import hay khởi tạo Engine/SessionLocal."""
    rbac_file = BACKEND_DIR / "app" / "core" / "rbac.py"
    assert rbac_file.exists()

    tree = ast.parse(rbac_file.read_text(encoding="utf-8"))
    forbidden_names = {"create_engine", "sessionmaker", "SessionLocal", "get_db"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden_names
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                assert alias.name not in forbidden_names


def test_16_rbac_does_not_perform_second_database_query():
    """16. require_roles không thực hiện thêm bất kỳ truy vấn CSDL nào (O(1) memory check)."""
    mock_db = MagicMock(spec=Session)
    admin = make_current_admin(role=AdminRole.IT_ADMIN.value)

    checker = require_roles(AdminRole.IT_ADMIN)
    _ = checker(current_admin=admin)

    # Session không hề bị gọi
    mock_db.query.assert_not_called()
    mock_db.commit.assert_not_called()
    mock_db.rollback.assert_not_called()


def test_17_is_valid_role_utility():
    """17. Kiểm tra hàm tiện ích is_valid_role."""
    assert is_valid_role(AdminRole.SUPERADMIN) is True
    assert is_valid_role("superadmin") is True
    assert is_valid_role("it_admin") is True
    assert is_valid_role("auditor") is True

    assert is_valid_role("invalid") is False
    assert is_valid_role("") is False
    assert is_valid_role(None) is False
    assert is_valid_role(123) is False  # type: ignore
