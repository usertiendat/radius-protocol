"""
Bộ kiểm thử đơn vị cho Admin Authentication API (Login Endpoint) (Phase 0B - Step 3.4.5).
Kiểm thử độc lập với SQLite in-memory, Mock và Pydantic Validation, không kết nối MariaDB thật.
Bao gồm đầy đủ 17+ kiểm thử bắt buộc theo đặc tả Step 3.4.5.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Generator
from unittest.mock import MagicMock, patch

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import Request
from pydantic import ValidationError as PydanticValidationError
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.exception_handlers import (
    business_exception_handler,
    unhandled_exception_handler,
)
from app.core.exceptions import (
    ForbiddenError,
    ServiceUnavailableError,
    UnauthorizedError,
)
from app.core.security import hash_password
from app.database import Base
from app.main import app
from app.models.application import AppAdmin
from app.routers.admin_auth import login as admin_login
from app.schemas.admin_auth import (
    AdminInfoResponse,
    AdminLoginRequest,
    AdminLoginResponse,
)
from app.services.admin_token import AdminTokenClaims, AdminTokenService

TEST_SECRET_KEY = "test-jwt-secret-key-32-chars-long-for-safe-unit-testing"


def make_mock_request(path: str = "/api/v1/admin/auth/login", method: str = "POST") -> Request:
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
    """Tạo AdminTokenService với test secret key độc lập."""
    return AdminTokenService(secret_key=TEST_SECRET_KEY)


# =============================================================================
# 17 KIỂM THỬ BẮT BUỘC THEO ĐẶC TẢ STEP 3.4.5
# =============================================================================

def test_01_admin_login_success(sqlite_db_session: Session, test_token_service: AdminTokenService):
    """1. Đăng nhập thành công với thông tin quản trị viên hợp lệ (HTTP 200)."""
    payload = AdminLoginRequest(username="super_admin", password="SuperSecretPass123!")
    response = admin_login(payload=payload, db=sqlite_db_session, token_service=test_token_service)

    assert isinstance(response, AdminLoginResponse)
    assert response.token_type == "bearer"
    assert response.expires_in == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert isinstance(response.access_token, str)
    assert len(response.access_token) > 30

    assert isinstance(response.admin, AdminInfoResponse)
    assert response.admin.username == "super_admin"
    assert response.admin.role == "superadmin"
    assert response.admin.is_active is True
    assert response.admin.email == "admin@enterprise.local"


def test_02_token_can_be_verified_by_admin_token_service(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """2. Access Token trả về giải mã và xác minh hợp lệ qua AdminTokenService."""
    payload = AdminLoginRequest(username="super_admin", password="SuperSecretPass123!")
    response = admin_login(payload=payload, db=sqlite_db_session, token_service=test_token_service)

    claims = test_token_service.verify_access_token(response.access_token)
    assert isinstance(claims, AdminTokenClaims)
    assert claims.sub == str(response.admin.id)
    assert claims.role == "superadmin"
    assert claims.type == "access"


def test_03_response_does_not_contain_password(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """3. Response data tuyệt đối không chứa trường 'password'."""
    payload = AdminLoginRequest(username="super_admin", password="SuperSecretPass123!")
    response = admin_login(payload=payload, db=sqlite_db_session, token_service=test_token_service)

    res_dict = response.model_dump()
    assert "password" not in res_dict
    assert "password" not in res_dict["admin"]
    assert hasattr(response.admin, "password") is False


def test_04_response_does_not_contain_password_hash(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """4. Response data tuyệt đối không chứa trường 'password_hash'."""
    payload = AdminLoginRequest(username="super_admin", password="SuperSecretPass123!")
    response = admin_login(payload=payload, db=sqlite_db_session, token_service=test_token_service)

    res_dict = response.model_dump()
    assert "password_hash" not in res_dict
    assert "password_hash" not in res_dict["admin"]
    assert hasattr(response.admin, "password_hash") is False


def test_05_wrong_username_returns_401(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """5. Sai tên đăng nhập ném UnauthorizedError (HTTP 401, code: INVALID_CREDENTIALS)."""
    payload = AdminLoginRequest(username="non_existent_admin", password="AnyPassword123!")

    with pytest.raises(UnauthorizedError) as exc_info:
        admin_login(payload=payload, db=sqlite_db_session, token_service=test_token_service)

    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "INVALID_CREDENTIALS"
    assert exc_info.value.message == "Tên đăng nhập hoặc mật khẩu không chính xác."

    # Xác minh Global Exception Handler
    req = make_mock_request()
    resp = business_exception_handler(req, exc_info.value)
    assert resp.status_code == 401
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "INVALID_CREDENTIALS"


def test_06_wrong_password_returns_401(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """6. Sai mật khẩu ném UnauthorizedError (HTTP 401, code: INVALID_CREDENTIALS)."""
    payload = AdminLoginRequest(username="super_admin", password="WrongPassword999!")

    with pytest.raises(UnauthorizedError) as exc_info:
        admin_login(payload=payload, db=sqlite_db_session, token_service=test_token_service)

    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "INVALID_CREDENTIALS"
    assert exc_info.value.message == "Tên đăng nhập hoặc mật khẩu không chính xác."


def test_07_invalid_credentials_have_identical_error_contract(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """
    7. Hai trường hợp sai credentials (sai username và sai password) có cùng error contract:
    Cùng HTTP Status (401), cùng Error Code (INVALID_CREDENTIALS), và cùng Error Message.
    (Lưu ý: Test này kiểm tra tính nhất quán của API contract, không tuyên bố là bằng chứng timing attack tuyệt đối).
    """
    payload_bad_user = AdminLoginRequest(username="ghost_admin", password="SecretPass123!")
    payload_bad_pass = AdminLoginRequest(username="super_admin", password="WrongPass123!")

    with pytest.raises(UnauthorizedError) as exc_user:
        admin_login(payload=payload_bad_user, db=sqlite_db_session, token_service=test_token_service)

    with pytest.raises(UnauthorizedError) as exc_pass:
        admin_login(payload=payload_bad_pass, db=sqlite_db_session, token_service=test_token_service)

    assert exc_user.value.http_status == exc_pass.value.http_status == 401
    assert exc_user.value.code == exc_pass.value.code == "INVALID_CREDENTIALS"
    assert exc_user.value.message == exc_pass.value.message == "Tên đăng nhập hoặc mật khẩu không chính xác."


def test_08_inactive_admin_returns_403(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """8. Tài khoản bị vô hiệu hóa (is_active=False) ném ForbiddenError (HTTP 403, code: ACCOUNT_INACTIVE)."""
    payload = AdminLoginRequest(username="disabled_admin", password="DisabledPass123!")

    with pytest.raises(ForbiddenError) as exc_info:
        admin_login(payload=payload, db=sqlite_db_session, token_service=test_token_service)

    assert exc_info.value.http_status == 403
    assert exc_info.value.code == "ACCOUNT_INACTIVE"
    assert "vô hiệu hóa" in exc_info.value.message.lower()

    # Kiểm tra Global Exception Handler
    req = make_mock_request()
    resp = business_exception_handler(req, exc_info.value)
    assert resp.status_code == 403
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "ACCOUNT_INACTIVE"


def test_09_missing_username_raises_422():
    """9. Thiếu trường username trong payload kích hoạt Pydantic ValidationError (HTTP 422)."""
    with pytest.raises(PydanticValidationError) as exc_info:
        AdminLoginRequest.model_validate({"password": "SomePassword123!"})

    errors = exc_info.value.errors()
    assert any(err["loc"] == ("username",) for err in errors)


def test_10_missing_password_raises_422():
    """10. Thiếu trường password trong payload kích hoạt Pydantic ValidationError (HTTP 422)."""
    with pytest.raises(PydanticValidationError) as exc_info:
        AdminLoginRequest.model_validate({"username": "some_user"})

    errors = exc_info.value.errors()
    assert any(err["loc"] == ("password",) for err in errors)


def test_11_empty_or_whitespace_username_raises_422():
    """11. Username rỗng hoặc chỉ có khoảng trắng bị từ chối với ValidationError (HTTP 422)."""
    for bad_username in ["", "   ", "\t\n"]:
        with pytest.raises(PydanticValidationError) as exc_info:
            AdminLoginRequest(username=bad_username, password="ValidPassword123!")

        errors = exc_info.value.errors()
        assert any(err["loc"] == ("username",) for err in errors)


def test_12_empty_password_raises_422():
    """12. Password rỗng bị từ chối với ValidationError (HTTP 422)."""
    with pytest.raises(PydanticValidationError) as exc_info:
        AdminLoginRequest(username="valid_admin", password="")

    errors = exc_info.value.errors()
    assert any(err["loc"] == ("password",) for err in errors)


def test_13_missing_jwt_secret_returns_503(sqlite_db_session: Session):
    """13. JWT Secret chưa được cấu hình ném ServiceUnavailableError (HTTP 503)."""
    service_no_secret = AdminTokenService(secret_key="")
    payload = AdminLoginRequest(username="super_admin", password="SuperSecretPass123!")

    with pytest.raises(ServiceUnavailableError) as exc_info:
        admin_login(payload=payload, db=sqlite_db_session, token_service=service_no_secret)

    assert exc_info.value.http_status == 503
    assert exc_info.value.code == "SERVICE_UNAVAILABLE"


def test_14_database_error_does_not_leak_credentials():
    """14. Lỗi CSDL bất ngờ không làm rò rỉ database credentials trong response."""
    sensitive_db_url = "mysql+pymysql://admin:SuperSecretPass999@10.0.0.1:3306/radius_db"
    mock_db = MagicMock(spec=Session)
    mock_db.query.side_effect = OperationalError(
        statement="SELECT * FROM app_admins",
        params={},
        orig=Exception(f"Connection refused to {sensitive_db_url}"),
    )

    req = make_mock_request()
    try:
        payload = AdminLoginRequest(username="super_admin", password="AnyPass123!")
        token_service = AdminTokenService(secret_key=TEST_SECRET_KEY)
        admin_login(payload=payload, db=mock_db, token_service=token_service)
    except Exception as exc:
        resp = unhandled_exception_handler(req, exc)
        assert resp.status_code == 500
        data = json.loads(resp.body.decode("utf-8"))
        assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
        assert "SuperSecretPass999" not in resp.body.decode("utf-8")
        assert "10.0.0.1" not in resp.body.decode("utf-8")


def test_15_expires_in_reflects_actual_system_config(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """15. Trường expires_in phản ánh đúng cấu hình thời hạn thực tế của hệ thống."""
    payload = AdminLoginRequest(username="super_admin", password="SuperSecretPass123!")

    with patch.object(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 45):
        response = admin_login(payload=payload, db=sqlite_db_session, token_service=test_token_service)
        # 45 phút * 60 giây = 2700 giây
        assert response.expires_in == 2700


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


def test_16_existing_endpoints_preserved_in_application():
    """16. Bảo toàn các endpoint cũ: /health, /health/database, /auth/login không bị ảnh hưởng."""
    routes = _get_all_app_routes(app)
    route_dict = {path: methods for path, methods in routes}

    # 1. Endpoint cũ /health vẫn tồn tại
    assert "/health" in route_dict
    assert "GET" in route_dict["/health"]

    # 2. Endpoint cũ /health/database vẫn tồn tại
    assert "/health/database" in route_dict
    assert "GET" in route_dict["/health/database"]

    # 3. Endpoint cũ /auth/login (FreeRADIUS PAP) vẫn tồn tại nguyên vẹn
    assert "/auth/login" in route_dict
    assert "POST" in route_dict["/auth/login"]

    # 4. Endpoint mới /api/v1/admin/auth/login được đăng ký chuẩn xác
    assert "/api/v1/admin/auth/login" in route_dict
    assert "POST" in route_dict["/api/v1/admin/auth/login"]


def test_17_token_does_not_contain_password_or_secrets(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """17. JWT Access Token tuyệt đối không chứa password, password_hash hoặc secret."""
    payload = AdminLoginRequest(username="super_admin", password="SuperSecretPass123!")
    response = admin_login(payload=payload, db=sqlite_db_session, token_service=test_token_service)

    raw_token = response.access_token
    claims = test_token_service.verify_access_token(raw_token)

    assert "password" not in claims
    assert "password_hash" not in claims
    assert "SuperSecretPass123!" not in raw_token
    assert TEST_SECRET_KEY not in raw_token


def test_18_password_whitespace_preserved():
    """18. Schema bảo toàn ký tự khoảng trắng gốc của mật khẩu (không tự ý strip)."""
    # Mật khẩu có khoảng trắng ở đầu và cuối
    pass_with_spaces = "  SecretWithSpaces!  "
    req = AdminLoginRequest(username="valid_user", password=pass_with_spaces)
    assert req.password == pass_with_spaces
    assert len(req.password) == len(pass_with_spaces)
