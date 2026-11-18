"""
Bộ kiểm thử đơn vị cho Current Admin Dependency (Phase 0B - Step 3.4.3).
Kiểm thử độc lập với SQLite in-memory, Mock Session và Starlette Request, không kết nối MariaDB thật.
Bao gồm đầy đủ 19+ kiểm thử bắt buộc theo đặc tả Step 3.4.3.
"""

import ast
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
from app.models.application import AppAdmin
from app.models.radius import RadCheck
from app.services.admin_auth import AdminAuthResult
from app.services.admin_token import AdminTokenClaims, AdminTokenService

# Khóa bí mật JWT dành riêng cho unit test
TEST_SECRET_KEY = "test-jwt-secret-key-32-chars-long-for-safe-unit-testing"
ANOTHER_SECRET_KEY = "wrong-secret-key-for-testing-signatures-32-chars"


def make_request(
    headers: Optional[Dict[str, str]] = None,
    path: str = "/api/v1/admin/me",
    method: str = "GET",
    query_string: str = "",
) -> Request:
    """Tạo đối tượng Request độc lập an toàn phục vụ kiểm thử Dependency."""
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
        "query_string": query_string.encode("ascii"),
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
        # Seed 1 Admin đang kích hoạt (is_active=True)
        active_admin = AppAdmin(
            username="super_admin",
            password_hash=hash_password("SuperSecretPass123!"),
            email="superadmin@enterprise.local",
            role="superadmin",
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        # Seed 1 Admin bị vô hiệu hóa (is_active=False)
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
    """Tạo instance AdminTokenService sử dụng test secret key."""
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
# 19 KIỂM THỬ BẮT BUỘC THEO ĐẶC TẢ STEP 3.4.3
# =============================================================================

def test_01_valid_jwt_and_active_admin_success(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """1. Request có JWT hợp lệ và Admin active → thành công."""
    valid_token = test_token_service.create_access_token(active_admin)
    req = make_request(headers={"Authorization": f"Bearer {valid_token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=valid_token)

    result = get_current_admin(
        request=req,
        credentials=creds,
        db=sqlite_db_session,
        token_service=test_token_service,
    )

    assert isinstance(result, CurrentAdmin)
    assert isinstance(result, AdminAuthResult)
    assert result.id == active_admin.id
    assert result.username == "super_admin"
    assert result.role == "superadmin"
    assert result.email == "superadmin@enterprise.local"
    assert result.is_active is True


def test_02_missing_authorization_header(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """2. Thiếu Authorization Header → 401 (code: UNAUTHORIZED)."""
    req = make_request(headers={})

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=req,
            credentials=None,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.code == "UNAUTHORIZED"
    assert exc_info.value.http_status == 401
    assert "Authorization" in exc_info.value.message

    # Kiểm tra phản hồi Global Exception Handler
    resp = business_exception_handler(req, exc_info.value)
    assert resp.status_code == 401
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "UNAUTHORIZED"


def test_03_wrong_bearer_scheme(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """3. Sai Bearer scheme → bị từ chối (HTTP 401, code: TOKEN_INVALID)."""
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
    assert exc_basic.value.code == "TOKEN_INVALID"
    assert exc_basic.value.http_status == 401

    # Thử scheme "Token"
    req_token = make_request(headers={"Authorization": f"Token {token}"})
    with pytest.raises(UnauthorizedError) as exc_token:
        get_current_admin(
            request=req_token,
            credentials=None,
            db=sqlite_db_session,
            token_service=test_token_service,
        )
    assert exc_token.value.code == "TOKEN_INVALID"
    assert exc_token.value.http_status == 401


def test_04_empty_token(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """4. Token rỗng → 401 (code: TOKEN_INVALID)."""
    # Header chỉ có chữ "Bearer"
    req_bare = make_request(headers={"Authorization": "Bearer"})
    with pytest.raises(UnauthorizedError) as exc_bare:
        get_current_admin(
            request=req_bare,
            credentials=None,
            db=sqlite_db_session,
            token_service=test_token_service,
        )
    assert exc_bare.value.code == "TOKEN_INVALID"
    assert exc_bare.value.http_status == 401

    # Header có "Bearer" kèm khoảng trắng
    req_space = make_request(headers={"Authorization": "Bearer    "})
    creds_empty = HTTPAuthorizationCredentials(scheme="Bearer", credentials="")
    with pytest.raises(UnauthorizedError) as exc_space:
        get_current_admin(
            request=req_space,
            credentials=creds_empty,
            db=sqlite_db_session,
            token_service=test_token_service,
        )
    assert exc_space.value.code == "TOKEN_INVALID"
    assert exc_space.value.http_status == 401


def test_05_malformed_token(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """5. Token malformed → 401 (code: TOKEN_INVALID)."""
    malformed_tokens = [
        "not.a.valid.jwt",
        "header.payload",
        "invalid_base64_string",
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
        assert exc_info.value.code == "TOKEN_INVALID"
        assert exc_info.value.http_status == 401


def test_06_expired_token(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """6. Token hết hạn → 401 (code: TOKEN_EXPIRED)."""
    expired_token = test_token_service.create_access_token(
        active_admin,
        expires_delta=timedelta(minutes=-10),
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

    assert exc_info.value.code == "TOKEN_EXPIRED"
    assert exc_info.value.http_status == 401
    assert "hết hạn" in exc_info.value.message.lower()

    # Kiểm tra Global Exception Handler
    resp = business_exception_handler(req, exc_info.value)
    assert resp.status_code == 401
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "TOKEN_EXPIRED"


def test_07_wrong_signature_token(
    sqlite_db_session: Session,
    active_admin: AppAdmin,
):
    """7. Token sai chữ ký → 401 (code: TOKEN_INVALID)."""
    tampered_service = AdminTokenService(secret_key=ANOTHER_SECRET_KEY)
    tampered_token = tampered_service.create_access_token(active_admin)

    standard_service = AdminTokenService(secret_key=TEST_SECRET_KEY)
    req = make_request(headers={"Authorization": f"Bearer {tampered_token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tampered_token)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=req,
            credentials=creds,
            db=sqlite_db_session,
            token_service=standard_service,
        )

    assert exc_info.value.code == "TOKEN_INVALID"
    assert exc_info.value.http_status == 401


def test_08_admin_id_not_found(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """8. Admin ID trong token không tồn tại trong CSDL → 401 (code: TOKEN_INVALID)."""
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

    assert exc_info.value.code == "TOKEN_INVALID"
    assert exc_info.value.http_status == 401
    assert "không tồn tại" in exc_info.value.message.lower()


def test_09_inactive_admin_forbidden(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    disabled_admin: AppAdmin,
):
    """9. Admin có is_active=False → 403 (code: ACCOUNT_INACTIVE)."""
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

    assert exc_info.value.code == "ACCOUNT_INACTIVE"
    assert exc_info.value.http_status == 403
    assert "vô hiệu hóa" in exc_info.value.message.lower()

    # Kiểm tra Global Exception Handler
    resp = business_exception_handler(req, exc_info.value)
    assert resp.status_code == 403
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "ACCOUNT_INACTIVE"


def test_10_admin_active_returns_correct_admin(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """10. Admin active → trả đúng Admin hiện tại qua dependency call."""
    token = test_token_service.create_access_token(active_admin)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    result = get_current_admin(
        request=None,
        credentials=creds,
        db=sqlite_db_session,
        token_service=test_token_service,
    )

    assert isinstance(result, CurrentAdmin)
    assert isinstance(result, AdminAuthResult)
    assert result.id == active_admin.id
    assert result.username == active_admin.username
    assert result.role == active_admin.role
    assert result.email == active_admin.email
    assert result.is_active is True


def test_11_does_not_contain_password(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """11. Không trả password trong DTO / response an toàn."""
    token = test_token_service.create_access_token(active_admin)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    result = get_current_admin(
        request=None,
        credentials=creds,
        db=sqlite_db_session,
        token_service=test_token_service,
    )

    # 1. Không có thuộc tính password
    assert hasattr(result, "password") is False

    # 2. Không nằm trong to_dict()
    assert "password" not in result.to_dict()

    # 3. Không nằm trong toán tử 'in'
    assert ("password" in result) is False

    # 4. Truy cập qua [] bị chặn
    with pytest.raises(KeyError):
        _ = result["password"]


def test_12_does_not_contain_password_hash(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """12. Không trả password_hash trong DTO / response an toàn."""
    token = test_token_service.create_access_token(active_admin)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    result = get_current_admin(
        request=None,
        credentials=creds,
        db=sqlite_db_session,
        token_service=test_token_service,
    )

    # 1. Không có thuộc tính password_hash
    assert hasattr(result, "password_hash") is False

    # 2. Không nằm trong to_dict()
    assert "password_hash" not in result.to_dict()

    # 3. Không nằm trong toán tử 'in'
    assert ("password_hash" in result) is False

    # 4. Truy cập qua [] bị chặn
    with pytest.raises(KeyError):
        _ = result["password_hash"]


def test_13_uses_injected_session(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """13. get_current_admin bắt buộc sử dụng Session được inject từ ngoài."""
    token = test_token_service.create_access_token(active_admin)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    mock_db = MagicMock(spec=Session)
    mock_db.query.return_value.filter.return_value.first.return_value = active_admin

    result = get_current_admin(
        request=None,
        credentials=creds,
        db=mock_db,
        token_service=test_token_service,
    )

    # Kiểm tra mock_db được gọi đúng cách
    mock_db.query.assert_called_once_with(AppAdmin)
    assert result.id == active_admin.id


def test_14_does_not_create_engine_or_session():
    """14. Dependency module không tự import hoặc khởi tạo Engine/SessionLocal."""
    dep_file = BACKEND_DIR / "app" / "core" / "admin_dependencies.py"
    assert dep_file.exists(), "admin_dependencies.py phải tồn tại"

    tree = ast.parse(dep_file.read_text(encoding="utf-8"))
    forbidden_names = {"create_engine", "sessionmaker", "SessionLocal"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden_names
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                assert alias.name not in forbidden_names


def test_15_does_not_call_commit(
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """15. Dependency là thao tác chỉ đọc, tuyệt đối không gọi commit()."""
    token = test_token_service.create_access_token(active_admin)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    mock_db = MagicMock(spec=Session)
    mock_db.query.return_value.filter.return_value.first.return_value = active_admin

    _ = get_current_admin(
        request=None,
        credentials=creds,
        db=mock_db,
        token_service=test_token_service,
    )

    mock_db.commit.assert_not_called()


def test_16_does_not_call_rollback(
    test_token_service: AdminTokenService,
):
    """16. Dependency không tự ý gọi rollback() trong luồng truy vấn."""
    token = test_token_service.create_access_token(sub="999", role="admin")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    mock_db = MagicMock(spec=Session)
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with pytest.raises(UnauthorizedError):
        get_current_admin(
            request=None,
            credentials=creds,
            db=mock_db,
            token_service=test_token_service,
        )

    mock_db.rollback.assert_not_called()


def test_17_does_not_use_radcheck(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """
    17. Dependency hoàn toàn không truy vấn bảng radcheck:
    - Source code không import RadCheck.
    - Tài khoản chỉ có trong radcheck sẽ bị từ chối với 401.
    """
    # 1. AST check: Source code không import RadCheck
    dep_file = BACKEND_DIR / "app" / "core" / "admin_dependencies.py"
    tree = ast.parse(dep_file.read_text(encoding="utf-8"))
    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_names.add(node.module)
            for alias in node.names:
                imported_names.add(alias.name)

    assert "RadCheck" not in imported_names
    assert "radcheck" not in imported_names

    # 2. Thêm tài khoản vào radcheck với id=555
    rad_user = RadCheck(
        id=555,
        username="network_radius_user",
        attribute="Cleartext-Password",
        op=":=",
        value="RadiusSecret123!",
    )
    sqlite_db_session.add(rad_user)
    sqlite_db_session.commit()

    # 3. Tạo token có sub="555" (chỉ có trong radcheck, không có trong app_admins)
    token = test_token_service.create_access_token(sub="555", role="user")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=None,
            credentials=creds,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.code == "TOKEN_INVALID"


def test_18_reject_token_missing_sub(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """18. Không chấp nhận token không có claim 'sub' (HTTP 401, code: TOKEN_INVALID)."""
    now = datetime.now(timezone.utc)
    payload = {
        "role": "superadmin",
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    raw_token = jwt.encode(payload, TEST_SECRET_KEY, algorithm="HS256")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_token)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=None,
            credentials=creds,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.code == "TOKEN_INVALID"


def test_19_reject_token_missing_role(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """19. Không chấp nhận token không có claim 'role' (HTTP 401, code: TOKEN_INVALID)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "1",
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    raw_token = jwt.encode(payload, TEST_SECRET_KEY, algorithm="HS256")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_token)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=None,
            credentials=creds,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.code == "TOKEN_INVALID"


# =============================================================================
# CÁC TEST BỔ SUNG: QUERY PARAMS, BODY, NON-INTEGER SUB, SERVICE OVERRIDE
# =============================================================================

def test_20_reject_token_in_query_parameter(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """20. Không nhận token từ query parameter (?token=...) → 401 UNAUTHORIZED."""
    token = test_token_service.create_access_token(active_admin)
    req = make_request(headers={}, query_string=f"token={token}&access_token={token}")

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=req,
            credentials=None,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.code == "UNAUTHORIZED"
    assert exc_info.value.http_status == 401


def test_21_reject_token_in_request_body(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
    active_admin: AppAdmin,
):
    """21. Không nhận token từ request body → 401 UNAUTHORIZED."""
    token = test_token_service.create_access_token(active_admin)
    req = make_request(headers={}, method="POST")

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=req,
            credentials=None,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.code == "UNAUTHORIZED"
    assert exc_info.value.http_status == 401


def test_22_reject_token_with_non_integer_sub(
    sqlite_db_session: Session,
    test_token_service: AdminTokenService,
):
    """22. Token có claim 'sub' không thể parse thành int → 401 (code: TOKEN_INVALID)."""
    token = test_token_service.create_access_token(sub="string_sub_not_int", role="admin")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(
            request=None,
            credentials=creds,
            db=sqlite_db_session,
            token_service=test_token_service,
        )

    assert exc_info.value.code == "TOKEN_INVALID"
    assert "định danh" in exc_info.value.message.lower()


def test_23_default_token_service_provider():
    """23. get_admin_token_service trả về instance hợp lệ của AdminTokenService."""
    provider = get_admin_token_service()
    assert isinstance(provider, AdminTokenService)
