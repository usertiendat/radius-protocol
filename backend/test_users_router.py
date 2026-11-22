"""
Bộ kiểm thử bảo mật Authentication & RBAC cho Users Router (Phase 0B - Step 1.2).
Kiểm tra các trường hợp bắt buộc:
1. Không có JWT (HTTP 401).
2. JWT không hợp lệ / sai chữ ký (HTTP 401).
3. JWT hết hạn (HTTP 401).
4. Đúng JWT nhưng sai quyền / role không cho phép (HTTP 403).
5. Admin hợp lệ và đủ quyền (HTTP 200/201).
6. Admin bị vô hiệu hóa is_active=False (HTTP 403).
7. Các chức năng CRUD Người dùng vẫn hoạt động chính xác.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Dict, Generator, Optional

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
from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.rbac import AdminRole
from app.core.security import hash_password
from app.database import Base
from app.main import app
from app.models import AppAdmin, AppUser, RadCheck, RadUserGroup
from app.routers.users import (
    READ_ROLES,
    WRITE_ROLES,
    create_user,
    delete_user,
    get_user_by_username,
    get_users,
    require_user_read,
    require_user_write,
    update_user,
)
from app.schemas.user import UserCreate, UserUpdate
from app.services.admin_token import AdminTokenService

TEST_SECRET_KEY = "test-jwt-secret-key-32-chars-long-for-safe-unit-testing"
ANOTHER_SECRET_KEY = "another-wrong-secret-key-for-testing-signatures-32c"


def make_request(headers: Optional[Dict[str, str]] = None, path: str = "/api/v1/users", method: str = "GET") -> Request:
    raw_headers = []
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode("ascii"),
        "headers": raw_headers,
        "query_string": b"",
    }
    return Request(scope)


@pytest.fixture
def test_db_session() -> Generator[Session, None, None]:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    tables = [
        AppAdmin.__table__,
        AppUser.__table__,
        RadCheck.__table__,
        RadUserGroup.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSession()

    try:
        superadmin = AppAdmin(
            id=1,
            username="super_user",
            password_hash=hash_password("SuperSecretPass123!"),
            email="super@enterprise.local",
            role=AdminRole.SUPERADMIN.value,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        it_admin = AppAdmin(
            id=2,
            username="it_user",
            password_hash=hash_password("ItSecretPass123!"),
            email="it@enterprise.local",
            role=AdminRole.IT_ADMIN.value,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        auditor = AppAdmin(
            id=3,
            username="auditor_user",
            password_hash=hash_password("AuditSecretPass123!"),
            email="audit@enterprise.local",
            role=AdminRole.AUDITOR.value,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        inactive_admin = AppAdmin(
            id=4,
            username="inactive_user",
            password_hash=hash_password("InactivePass123!"),
            email="inactive@enterprise.local",
            role=AdminRole.IT_ADMIN.value,
            is_active=False,
            created_at=datetime.now(timezone.utc),
        )
        session.add_all([superadmin, it_admin, auditor, inactive_admin])
        session.commit()
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine, tables=tables)
        engine.dispose()


@pytest.fixture
def token_service() -> AdminTokenService:
    return AdminTokenService(secret_key=TEST_SECRET_KEY)


# =============================================================================
# 1. KIỂM TRA ĐĂNG KÝ ROUTE
# =============================================================================

def test_user_routes_registered_in_fastapi_app():
    paths = set()
    for r in app.routes:
        if hasattr(r, "path") and r.path:
            paths.add(r.path)
        elif hasattr(r, "original_router"):
            for sub_r in r.original_router.routes:
                paths.add(sub_r.path)
    assert "/api/v1/users" in paths
    assert "/api/v1/users/{username}" in paths


# =============================================================================
# 2. KIỂM TRA AUTHENTICATION & RBAC TỪNG TRƯỜNG HỢP
# =============================================================================

def test_missing_jwt_raises_unauthorized(test_db_session: Session, token_service: AdminTokenService):
    """1. Không có Authorization header -> HTTP 401 Unauthorized."""
    req = make_request()
    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(request=req, credentials=None, db=test_db_session, token_service=token_service)
    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "UNAUTHORIZED"


def test_invalid_jwt_signature_raises_unauthorized(test_db_session: Session):
    """2. JWT có chữ ký sai / secret key khác -> HTTP 401 Unauthorized."""
    wrong_service = AdminTokenService(secret_key=ANOTHER_SECRET_KEY)
    token = wrong_service.create_access_token(sub="1", role="superadmin")
    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    real_service = AdminTokenService(secret_key=TEST_SECRET_KEY)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(request=req, credentials=creds, db=test_db_session, token_service=real_service)
    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "TOKEN_INVALID"


def test_expired_jwt_raises_unauthorized(test_db_session: Session, token_service: AdminTokenService):
    """3. JWT đã hết hạn -> HTTP 401 Unauthorized."""
    token = token_service.create_access_token(sub="1", role="superadmin", expires_delta=timedelta(seconds=-10))
    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(request=req, credentials=creds, db=test_db_session, token_service=token_service)
    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "TOKEN_EXPIRED"


def test_auditor_denied_write_access(test_db_session: Session, token_service: AdminTokenService):
    """4. Auditor có token hợp lệ nhưng bị từ chối quyền Ghi (POST/PUT/DELETE) -> HTTP 403 Forbidden."""
    token = token_service.create_access_token(sub="3", role=AdminRole.AUDITOR.value)
    req = make_request(headers={"Authorization": f"Bearer {token}"}, method="POST")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    admin = get_current_admin(request=req, credentials=creds, db=test_db_session, token_service=token_service)
    assert admin.role == AdminRole.AUDITOR.value

    # Kiểm tra require_user_write từ chối auditor
    with pytest.raises(ForbiddenError) as exc_info:
        require_user_write(current_admin=admin)
    assert exc_info.value.http_status == 403
    assert exc_info.value.code == "FORBIDDEN"


def test_inactive_admin_raises_forbidden(test_db_session: Session, token_service: AdminTokenService):
    """6. Admin bị vô hiệu hóa is_active=False -> HTTP 403 ACCOUNT_INACTIVE."""
    token = token_service.create_access_token(sub="4", role=AdminRole.IT_ADMIN.value)
    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(ForbiddenError) as exc_info:
        get_current_admin(request=req, credentials=creds, db=test_db_session, token_service=token_service)
    assert exc_info.value.http_status == 403
    assert exc_info.value.code == "ACCOUNT_INACTIVE"


def test_superadmin_and_it_admin_granted_write_access():
    """5. Superadmin và IT_Admin được cấp quyền Ghi (Write)."""
    super_admin = CurrentAdmin(id=1, username="super", email="s@e.l", role=AdminRole.SUPERADMIN.value, is_active=True)
    it_admin = CurrentAdmin(id=2, username="it", email="i@e.l", role=AdminRole.IT_ADMIN.value, is_active=True)

    assert require_user_write(current_admin=super_admin) is super_admin
    assert require_user_write(current_admin=it_admin) is it_admin


def test_all_three_roles_granted_read_access():
    """5b. Cả 3 vai trò (superadmin, it_admin, auditor) đều được cấp quyền Đọc (Read)."""
    super_admin = CurrentAdmin(id=1, username="super", email="s@e.l", role=AdminRole.SUPERADMIN.value, is_active=True)
    it_admin = CurrentAdmin(id=2, username="it", email="i@e.l", role=AdminRole.IT_ADMIN.value, is_active=True)
    auditor = CurrentAdmin(id=3, username="audit", email="a@e.l", role=AdminRole.AUDITOR.value, is_active=True)

    assert require_user_read(current_admin=super_admin) is super_admin
    assert require_user_read(current_admin=it_admin) is it_admin
    assert require_user_read(current_admin=auditor) is auditor


# =============================================================================
# 3. KIỂM TRA CHỨC NĂNG CRUD VẪN HOẠT ĐỘNG CHÍNH XÁC
# =============================================================================

def test_user_crud_flow_with_authorized_admin(test_db_session: Session):
    """7. Kiểm tra toàn bộ luồng CRUD người dùng với admin hợp lệ."""
    admin = CurrentAdmin(id=1, username="super", email="s@e.l", role=AdminRole.SUPERADMIN.value, is_active=True)

    # 1. Create
    created = create_user(
        data=UserCreate(username="john_doe", password="SecretPass123", fullname="John Doe", email="john@example.com"),
        db=test_db_session,
        current_admin=admin,
    )
    assert created.username == "john_doe"
    assert created.full_name == "John Doe"

    # 2. Get list (read query autobegins in SQLAlchemy, rollback closes the read transaction)
    users = get_users(skip=0, limit=10, db=test_db_session, current_admin=admin)
    assert any(u.username == "john_doe" for u in users)
    test_db_session.rollback()

    # 3. Get single
    user = get_user_by_username(username="john_doe", db=test_db_session, current_admin=admin)
    assert user.username == "john_doe"
    test_db_session.rollback()

    # 4. Update
    updated = update_user(
        username="john_doe",
        data=UserUpdate(fullname="John Updated", email="john_updated@example.com"),
        db=test_db_session,
        current_admin=admin,
    )
    assert updated.full_name == "John Updated"
    test_db_session.rollback()

    # 5. Delete
    resp = delete_user(username="john_doe", db=test_db_session, current_admin=admin)
    assert resp.status_code == 204
