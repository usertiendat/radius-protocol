"""
Bộ kiểm thử cho Admin Identity API (GET /api/v1/admin/auth/me) (Phase 0B - Step 3.4.6).
Bao gồm đầy đủ các cấp độ kiểm thử:
- Cấp độ A: Handler Tests (Kiểm tra logic xử lý của hàm endpoint get_me).
- Cấp độ B: Route Registration Tests (Kiểm tra đăng ký route và bảo toàn các endpoint cũ).
- Cấp độ C: Authentication & Security Pipeline Tests (Kiểm tra pipeline xác thực, từ chối token hỏng/hết hạn,
  kiểm tra CSDL và ánh xạ Global Exception Handlers).
Kiểm thử độc lập với SQLite in-memory, không kết nối MariaDB thật.
"""

from datetime import datetime, timedelta, timezone
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
import jwt
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
from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.security import hash_password
from app.database import Base
from app.main import app
from app.models.application import AppAdmin
from app.routers.admin_auth import get_me
from app.schemas.admin_auth import AdminInfoResponse
from app.services.admin_token import AdminTokenService

TEST_SECRET_KEY = "test-jwt-secret-key-32-chars-long-for-safe-unit-testing"
ANOTHER_SECRET_KEY = "another-wrong-secret-key-for-testing-signatures-32c"


def make_request(
    headers: Optional[Dict[str, str]] = None,
    path: str = "/api/v1/admin/auth/me",
    method: str = "GET",
) -> Request:
    """Tạo đối tượng Request độc lập an toàn phục vụ kiểm thử."""
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
        active_admin = AppAdmin(
            username="super_admin",
            password_hash=hash_password("SuperSecretPass123!"),
            email="admin@enterprise.local",
            role="superadmin",
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        disabled_admin = AppAdmin(
            username="disabled_admin",
            password_hash=hash_password("DisabledPass123!"),
            email="disabled@enterprise.local",
            role="auditor",
            is_active=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(active_admin)
        session.add(disabled_admin)
        session.commit()

        yield session
    finally:
        session.close()


@pytest.fixture
def test_token_service() -> AdminTokenService:
    """Tạo instance AdminTokenService với test secret key."""
    return AdminTokenService(secret_key=TEST_SECRET_KEY)


@pytest.fixture
def active_admin(sqlite_db_session: Session) -> AppAdmin:
    """Lấy đối tượng active_admin từ DB."""
    admin = sqlite_db_session.query(AppAdmin).filter(AppAdmin.username == "super_admin").first()
    assert admin is not None
    return admin


@pytest.fixture
def disabled_admin(sqlite_db_session: Session) -> AppAdmin:
    """Lấy đối tượng disabled_admin từ DB."""
    admin = sqlite_db_session.query(AppAdmin).filter(AppAdmin.username == "disabled_admin").first()
    assert admin is not None
    return admin


# =============================================================================
# CẤP ĐỘ A: HANDLER TESTS (Kiểm tra logic xử lý của hàm endpoint get_me)
# =============================================================================

def test_01_handler_returns_correct_admin_info():
    """A1. Handler get_me nhận CurrentAdmin và trả về đúng AdminInfoResponse."""
    now = datetime.now(timezone.utc)
    current_admin = CurrentAdmin(
        id=10,
        username="it_operator",
        email="operator@enterprise.local",
        role="it_admin",
        is_active=True,
        created_at=now,
    )

    response = get_me(current_admin=current_admin)

    assert isinstance(response, AdminInfoResponse)
    assert response.id == 10
    assert response.username == "it_operator"
    assert response.email == "operator@enterprise.local"
    assert response.role == "it_admin"
    assert response.is_active is True
    assert response.created_at == now


def test_02_handler_does_not_contain_password_or_sensitive_data():
    """A2. Response model từ handler tuyệt đối không chứa password, password_hash hoặc secret."""
    current_admin = CurrentAdmin(
        id=1,
        username="super_admin",
        email="admin@enterprise.local",
        role="superadmin",
        is_active=True,
    )

    response = get_me(current_admin=current_admin)
    res_dict = response.model_dump()

    # Không chứa password hay password_hash
    assert "password" not in res_dict
    assert "password_hash" not in res_dict
    assert hasattr(response, "password") is False
    assert hasattr(response, "password_hash") is False


def test_03_handler_does_not_perform_database_query():
    """A3. Handler get_me là thao tác ánh xạ bộ nhớ O(1), tuyệt đối không truy vấn DB lần thứ hai."""
    mock_session = MagicMock(spec=Session)
    current_admin = CurrentAdmin(
        id=5,
        username="auditor_user",
        email="audit@enterprise.local",
        role="auditor",
        is_active=True,
    )

    _ = get_me(current_admin=current_admin)

    # Session hoàn toàn không bị gọi trong handler
    mock_session.query.assert_not_called()
    mock_session.commit.assert_not_called()
    mock_session.rollback.assert_not_called()


# =============================================================================
# CẤP ĐỘ B: ROUTE REGISTRATION TESTS (Kiểm tra đăng ký route trong ứng dụng)
# =============================================================================

def test_04_get_me_route_is_registered_in_fastapi_app():
    """B1. Route GET /api/v1/admin/auth/me được đăng ký chuẩn xác trong FastAPI application."""
    routes = _get_all_app_routes(app)
    route_dict = {path: methods for path, methods in routes}

    assert "/api/v1/admin/auth/me" in route_dict
    assert "GET" in route_dict["/api/v1/admin/auth/me"]


def test_05_existing_endpoints_preserved_in_application():
    """B2. Toàn bộ các endpoint cũ (/health, /health/database, /auth/login, /login) được bảo toàn nguyên vẹn."""
    routes = _get_all_app_routes(app)
    route_dict = {path: methods for path, methods in routes}

    # Endpoint cũ /health
    assert "/health" in route_dict
    assert "GET" in route_dict["/health"]

    # Endpoint cũ /health/database
    assert "/health/database" in route_dict
    assert "GET" in route_dict["/health/database"]

    # Endpoint cũ /auth/login (FreeRADIUS PAP)
    assert "/auth/login" in route_dict
    assert "POST" in route_dict["/auth/login"]

    # Endpoint login của Admin: /api/v1/admin/auth/login
    assert "/api/v1/admin/auth/login" in route_dict
    assert "POST" in route_dict["/api/v1/admin/auth/login"]


# =============================================================================
# CẤP ĐỘ C: AUTHENTICATION & SECURITY PIPELINE TESTS (Kiểm tra quy trình xác thực)
# =============================================================================

def test_06_valid_jwt_and_active_admin_returns_success(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """C1. Token hợp lệ của Admin đang hoạt động → trả về đúng thông tin Admin (HTTP 200)."""
    valid_token = test_token_service.create_access_token(active_admin)
    req = make_request(headers={"Authorization": f"Bearer {valid_token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=valid_token)

    # 1. Pipeline xác thực qua get_current_admin
    current_admin = get_current_admin(
        request=req,
        credentials=creds,
        db=sqlite_db_session,
        token_service=test_token_service,
    )

    # 2. Chuyển giao vào handler get_me
    response = get_me(current_admin=current_admin)

    assert isinstance(response, AdminInfoResponse)
    assert response.id == active_admin.id
    assert response.username == "super_admin"
    assert response.email == "admin@enterprise.local"
    assert response.role == "superadmin"
    assert response.is_active is True


def test_07_missing_authorization_header_raises_401(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """C2. Thiếu Authorization header → 401 Unauthorized (code: UNAUTHORIZED)."""
    req = make_request(headers={})

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=req,
            credentials=None,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "UNAUTHORIZED"
    assert "Authorization" in exc_info.value.message

    # Kiểm tra Global Exception Handler
    resp = business_exception_handler(req, exc_info.value)
    assert resp.status_code == 401
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "UNAUTHORIZED"


def test_08_wrong_bearer_scheme_raises_401(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """C3. Sai Bearer scheme (Basic, Token,...) → 401 Unauthorized (code: TOKEN_INVALID)."""
    token = test_token_service.create_access_token(active_admin)

    # Thử scheme "Basic"
    req_basic = make_request(headers={"Authorization": f"Basic {token}"})
    with pytest.raises(UnauthorizedError) as exc_basic:
        get_current_admin(
            request=req_basic,
            credentials=None,
            db=sqlite_db_session,
            token_service=test_token_service,
        )
    assert exc_basic.value.http_status == 401
    assert exc_basic.value.code == "TOKEN_INVALID"

    # Thử scheme "Token"
    req_token = make_request(headers={"Authorization": f"Token {token}"})
    with pytest.raises(UnauthorizedError) as exc_token:
        get_current_admin(
            request=req_token,
            credentials=None,
            db=sqlite_db_session,
            token_service=test_token_service,
        )
    assert exc_token.value.http_status == 401
    assert exc_token.value.code == "TOKEN_INVALID"


def test_09_malformed_token_raises_401(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """C4. Token sai định dạng hoặc chuỗi rác → 401 Unauthorized (code: TOKEN_INVALID)."""
    malformed_tokens = [
        "not.a.valid.jwt",
        "header.payload",
        "corrupted_token_string",
    ]
    for bad_token in malformed_tokens:
        req = make_request(headers={"Authorization": f"Bearer {bad_token}"})
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=bad_token)
        with pytest.raises(UnauthorizedError) as exc_info:
            get_current_admin(
                request=req,
                credentials=creds,
                db=sqlite_db_session,
                token_service=test_token_service,
            )
        assert exc_info.value.http_status == 401
        assert exc_info.value.code == "TOKEN_INVALID"


def test_10_wrong_signature_token_raises_401(
    sqlite_db_session: Session,
    active_admin: AppAdmin,
):
    """C5. Token sai chữ ký số (ký bằng khóa bí mật khác) → 401 Unauthorized (code: TOKEN_INVALID)."""
    other_service = AdminTokenService(secret_key=ANOTHER_SECRET_KEY)
    tampered_token = other_service.create_access_token(active_admin)

    req = make_request(headers={"Authorization": f"Bearer {tampered_token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tampered_token)

    standard_service = AdminTokenService(secret_key=TEST_SECRET_KEY)
    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=req,
            credentials=creds,
            db=sqlite_db_session,
            token_service=standard_service,
        )

    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "TOKEN_INVALID"


def test_11_expired_token_raises_401(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """C6. Token đã hết hạn → 401 Unauthorized (code: TOKEN_EXPIRED)."""
    expired_token = test_token_service.create_access_token(
        active_admin,
        expires_delta=timedelta(minutes=-5),
    )
    req = make_request(headers={"Authorization": f"Bearer {expired_token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=req,
            credentials=creds,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "TOKEN_EXPIRED"
    assert "hết hạn" in exc_info.value.message.lower()

    # Kiểm tra Global Exception Handler
    resp = business_exception_handler(req, exc_info.value)
    assert resp.status_code == 401
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "TOKEN_EXPIRED"


def test_12_wrong_token_type_raises_401(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """C7. Token sai claim 'type' (không phải 'access', ví dụ 'refresh') → 401 (code: TOKEN_INVALID)."""
    now = datetime.now(timezone.utc)
    payload_refresh = {
        "sub": "1",
        "role": "superadmin",
        "type": "refresh",  # Sai type
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    refresh_token = jwt.encode(payload_refresh, TEST_SECRET_KEY, algorithm="HS256")
    req = make_request(headers={"Authorization": f"Bearer {refresh_token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=refresh_token)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=req,
            credentials=creds,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "TOKEN_INVALID"


def test_13_admin_not_found_raises_401(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """C8. Token chứa Admin ID không tồn tại trong CSDL → 401 (code: TOKEN_INVALID)."""
    non_existent_token = test_token_service.create_access_token(
        sub="9999",
        role="superadmin",
    )
    req = make_request(headers={"Authorization": f"Bearer {non_existent_token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=non_existent_token)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=req,
            credentials=creds,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "TOKEN_INVALID"
    assert "không tồn tại" in exc_info.value.message.lower()


def test_14_inactive_admin_raises_403(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    disabled_admin: AppAdmin,
):
    """C9. Admin có is_active=False trong CSDL → 403 Forbidden (code: ACCOUNT_INACTIVE)."""
    token = test_token_service.create_access_token(disabled_admin)
    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(ForbiddenError) as exc_info:
        get_current_admin(
            request=req,
            credentials=creds,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.http_status == 403
    assert exc_info.value.code == "ACCOUNT_INACTIVE"
    assert "vô hiệu hóa" in exc_info.value.message.lower()

    # Kiểm tra Global Exception Handler
    resp = business_exception_handler(req, exc_info.value)
    assert resp.status_code == 403
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "ACCOUNT_INACTIVE"


def test_15_role_change_in_database_is_reflected_in_response(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """
    C10. Vai trò thay đổi trong CSDL được phản ánh ngay lập tức vào response:
    - Admin nhận token khi có role='superadmin'.
    - Sau đó trong CSDL, role bị hạ xuống 'auditor'.
    - Endpoint get_me phải phản ánh đúng role mới từ CSDL ('auditor'), không dùng claim cũ trong token.
    """
    admin_db = sqlite_db_session.query(AppAdmin).filter(AppAdmin.username == "super_admin").first()
    assert admin_db is not None
    assert admin_db.role == "superadmin"

    # Token được tạo với claim role="superadmin"
    token = test_token_service.create_access_token(admin_db)

    # CSDL cập nhật vai trò mới: "auditor"
    admin_db.role = "auditor"
    sqlite_db_session.commit()

    # Truy cập endpoint GET /me
    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    current_admin = get_current_admin(
        request=req,
        credentials=creds,
        db=sqlite_db_session,
        token_service=test_token_service,
    )
    response = get_me(current_admin=current_admin)

    # Khẳng định role là 'auditor' theo đúng CSDL
    assert response.role == "auditor"
    assert response.role != "superadmin"


def test_16_response_does_not_contain_secrets_or_db_info(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """C11. Response của get_me tuyệt đối không chứa password, password_hash, JWT secret hay DB info."""
    token = test_token_service.create_access_token(active_admin)
    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    current_admin = get_current_admin(
        request=req,
        credentials=creds,
        db=sqlite_db_session,
        token_service=test_token_service,
    )
    response = get_me(current_admin=current_admin)
    res_dict = response.model_dump()

    # Kiểm tra toàn diện
    assert "password" not in res_dict
    assert "password_hash" not in res_dict
    assert "secret" not in res_dict
    assert hasattr(response, "password") is False
    assert hasattr(response, "password_hash") is False
