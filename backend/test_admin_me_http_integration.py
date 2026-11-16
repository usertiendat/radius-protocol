"""
HTTP Integration Tests cho Admin Identity API (GET /api/v1/admin/auth/me) (Phase 0B - Step 3.4.6-HF).
Thực hiện HTTP requests thực sự thông qua FastAPI ASGI application bằng HTTPX ASGITransport.

Đảm bảo yêu cầu đi qua toàn bộ pipeline:
1. FastAPI routing (/api/v1/admin/auth/me)
2. Dependency injection (tự động phân giải Depends(get_current_admin))
3. HTTP Authorization header (Bearer token extraction)
4. get_current_admin (xác minh token + kiểm tra CSDL + trạng thái hoạt động)
5. Global Exception Handlers (chuẩn hóa lỗi HTTP)
6. Response serialization (AdminInfoResponse DTO)

Cô lập kiểm thử với SQLite in-memory và test token service thông qua dependency_overrides.
Tuyệt đối không override get_current_admin.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import selectors
import socket
import sys
from typing import Dict, Generator, Optional

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Cấu hình môi trường ASGI tương thích Windows Sandbox
import asyncio.selector_events

def _make_self_pipe(self):
    self._dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self._dummy_sock.bind(("127.0.0.1", 0))
    self._dummy_sock.listen(1)
    self._dummy_sock.setblocking(False)
    self._selector.register(self._dummy_sock, selectors.EVENT_READ)
    self._ssock = self._dummy_sock
    self._csock = self._dummy_sock
    self._internal_fds += 1

def _close_self_pipe(self):
    if hasattr(self, "_dummy_sock") and self._dummy_sock:
        try:
            self._selector.unregister(self._dummy_sock)
        except Exception:
            pass
        self._dummy_sock.close()
        self._dummy_sock = None
        self._ssock = None
        self._csock = None
        self._internal_fds -= 1

def _write_to_self(self):
    pass

asyncio.selector_events.BaseSelectorEventLoop._make_self_pipe = _make_self_pipe
asyncio.selector_events.BaseSelectorEventLoop._close_self_pipe = _close_self_pipe
asyncio.selector_events.BaseSelectorEventLoop._write_to_self = _write_to_self
asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import anyio.to_thread
async def mock_run_sync(func, *args, cancellable=False, limiter=None):
    return func(*args)
anyio.to_thread.run_sync = mock_run_sync

import starlette.concurrency
async def mock_run_in_threadpool(func, *args, **kwargs):
    return func(*args, **kwargs)
starlette.concurrency.run_in_threadpool = mock_run_in_threadpool

import httpx
import jwt
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.admin_dependencies import get_admin_token_service
from app.core.security import hash_password
from app.database import Base, get_db
from app.main import app
from app.models.application import AppAdmin
from app.services.admin_token import AdminTokenService

TEST_SECRET_KEY = "test-jwt-secret-key-32-chars-long-for-safe-unit-testing"
ANOTHER_SECRET_KEY = "another-wrong-secret-key-for-testing-signatures-32c"


class ASGIHttpClient:
    """Client gửi HTTP request thực sự qua ASGI Application."""

    def __init__(self, application):
        self.app = application
        self.transport = httpx.ASGITransport(app=application)

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> httpx.Response:
        """Gửi HTTP GET request qua ASGI pipeline."""
        async def _send():
            async with httpx.AsyncClient(transport=self.transport, base_url="http://testserver") as client:
                return await client.get(url, headers=headers)
        return asyncio.run(_send())


@pytest.fixture
def sqlite_session() -> Generator[Session, None, None]:
    """Khởi tạo SQLite in-memory session cô lập cho từng test case."""
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
    """Cung cấp AdminTokenService dùng riêng cho test suite."""
    return AdminTokenService(secret_key=TEST_SECRET_KEY)


@pytest.fixture
def client(sqlite_session: Session, test_token_service: AdminTokenService) -> Generator[ASGIHttpClient, None, None]:
    """
    Thiết lập HTTP Client qua ASGI Application kèm dependency overrides.
    Chỉ override get_db và get_admin_token_service.
    TUYỆT ĐỐI KHÔNG override get_current_admin để đảm bảo dependency này được FastAPI thực thi.
    Tự động khôi phục app.dependency_overrides sau khi hoàn thành test.
    """
    def override_db():
        try:
            yield sqlite_session
        finally:
            pass

    def override_token_service():
        return test_token_service

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_admin_token_service] = override_token_service

    http_client = ASGIHttpClient(app)
    try:
        yield http_client
    finally:
        app.dependency_overrides.clear()


# =============================================================================
# CÁC TEST CASES HTTP INTEGRATION THỰC SỰ QUA ASGI APPLICATION
# =============================================================================

def test_01_http_valid_jwt_and_active_admin_returns_200(
    client: ASGIHttpClient,
    test_token_service: AdminTokenService,
    sqlite_session: Session,
):
    """1. Access Token hợp lệ, admin đang active → HTTP 200 OK + payload đầy đủ."""
    admin = sqlite_session.query(AppAdmin).filter(AppAdmin.username == "super_admin").first()
    assert admin is not None

    token = test_token_service.create_access_token(admin)
    response = client.get(
        "/api/v1/admin/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == admin.id
    assert data["username"] == "super_admin"
    assert data["email"] == "admin@enterprise.local"
    assert data["role"] == "superadmin"
    assert data["is_active"] is True
    assert "created_at" in data


def test_02_http_missing_authorization_header_returns_401(client: ASGIHttpClient):
    """2. Không có Authorization header → HTTP 401 Unauthorized (code UNAUTHORIZED)."""
    response = client.get("/api/v1/admin/auth/me")

    assert response.status_code == 401
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "UNAUTHORIZED"
    assert "Authorization" in data["error"]["message"]


def test_03_http_wrong_authorization_scheme_returns_401(
    client: ASGIHttpClient,
    test_token_service: AdminTokenService,
    sqlite_session: Session,
):
    """3. Sai Authorization scheme (Basic hoặc Token thay vì Bearer) → HTTP 401 (code TOKEN_INVALID)."""
    admin = sqlite_session.query(AppAdmin).filter(AppAdmin.username == "super_admin").first()
    token = test_token_service.create_access_token(admin)

    # Thử scheme Basic
    res_basic = client.get(
        "/api/v1/admin/auth/me",
        headers={"Authorization": f"Basic {token}"},
    )
    assert res_basic.status_code == 401
    assert res_basic.json()["error"]["code"] == "TOKEN_INVALID"

    # Thử scheme Token
    res_token = client.get(
        "/api/v1/admin/auth/me",
        headers={"Authorization": f"Token {token}"},
    )
    assert res_token.status_code == 401
    assert res_token.json()["error"]["code"] == "TOKEN_INVALID"


def test_04_http_wrong_signature_returns_401(
    client: ASGIHttpClient,
    sqlite_session: Session,
):
    """4. Token bị ký sai Secret Key → HTTP 401 Unauthorized (code TOKEN_INVALID)."""
    admin = sqlite_session.query(AppAdmin).filter(AppAdmin.username == "super_admin").first()
    other_service = AdminTokenService(secret_key=ANOTHER_SECRET_KEY)
    tampered_token = other_service.create_access_token(admin)

    response = client.get(
        "/api/v1/admin/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "TOKEN_INVALID"


def test_05_http_expired_token_returns_401_token_expired(
    client: ASGIHttpClient,
    test_token_service: AdminTokenService,
    sqlite_session: Session,
):
    """5. Token hết hạn → HTTP 401 Unauthorized (code TOKEN_EXPIRED)."""
    admin = sqlite_session.query(AppAdmin).filter(AppAdmin.username == "super_admin").first()
    expired_token = test_token_service.create_access_token(
        admin,
        expires_delta=timedelta(minutes=-10),
    )

    response = client.get(
        "/api/v1/admin/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "TOKEN_EXPIRED"
    assert "hết hạn" in data["error"]["message"].lower()


def test_06_http_wrong_token_type_returns_401(client: ASGIHttpClient):
    """6. Sai token type (ví dụ 'type=refresh') → HTTP 401 Unauthorized (code TOKEN_INVALID)."""
    now = datetime.now(timezone.utc)
    payload_refresh = {
        "sub": "1",
        "role": "superadmin",
        "type": "refresh",  # Sai type
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    refresh_token = jwt.encode(payload_refresh, TEST_SECRET_KEY, algorithm="HS256")

    response = client.get(
        "/api/v1/admin/auth/me",
        headers={"Authorization": f"Bearer {refresh_token}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "TOKEN_INVALID"


def test_07_http_non_existent_admin_returns_401(
    client: ASGIHttpClient,
    test_token_service: AdminTokenService,
):
    """7. Admin không còn tồn tại trong CSDL → HTTP 401 Unauthorized (code TOKEN_INVALID)."""
    token_non_existent = test_token_service.create_access_token(
        sub="99999",
        role="superadmin",
    )

    response = client.get(
        "/api/v1/admin/auth/me",
        headers={"Authorization": f"Bearer {token_non_existent}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "TOKEN_INVALID"
    assert "không tồn tại" in data["error"]["message"].lower()


def test_08_http_inactive_admin_returns_403_account_inactive(
    client: ASGIHttpClient,
    test_token_service: AdminTokenService,
    sqlite_session: Session,
):
    """8. Admin có is_active=False trong CSDL → HTTP 403 Forbidden (code ACCOUNT_INACTIVE)."""
    disabled = sqlite_session.query(AppAdmin).filter(AppAdmin.username == "disabled_admin").first()
    assert disabled is not None

    token_disabled = test_token_service.create_access_token(disabled)

    response = client.get(
        "/api/v1/admin/auth/me",
        headers={"Authorization": f"Bearer {token_disabled}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert data["error"]["code"] == "ACCOUNT_INACTIVE"
    assert "vô hiệu hóa" in data["error"]["message"].lower()


def test_09_http_role_updated_in_database_reflected_in_response(
    client: ASGIHttpClient,
    test_token_service: AdminTokenService,
    sqlite_session: Session,
):
    """
    9. Role được cập nhật trong CSDL → Response HTTP phản ánh role hiện tại (Database Authority):
    - Admin ban đầu có role='superadmin' và phát hành token với claim này.
    - CSDL cập nhật role thành 'auditor'.
    - Client gọi GET /me, response HTTP 200 phải trả về role='auditor'.
    """
    admin = sqlite_session.query(AppAdmin).filter(AppAdmin.username == "super_admin").first()
    token = test_token_service.create_access_token(admin)

    # Cập nhật vai trò trong CSDL
    admin.role = "auditor"
    sqlite_session.commit()

    response = client.get(
        "/api/v1/admin/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "auditor"
    assert data["role"] != "superadmin"


def test_10_http_response_does_not_contain_password_or_secrets(
    client: ASGIHttpClient,
    test_token_service: AdminTokenService,
    sqlite_session: Session,
):
    """10. Response HTTP 200 tuyệt đối không chứa password, password_hash, secret hoặc DB connection info."""
    admin = sqlite_session.query(AppAdmin).filter(AppAdmin.username == "super_admin").first()
    token = test_token_service.create_access_token(admin)

    response = client.get(
        "/api/v1/admin/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()

    # Rà soát triệt để các trường nhạy cảm
    assert "password" not in data
    assert "password_hash" not in data
    assert "secret" not in data
    assert "secret_key" not in data
    assert "database" not in data
    assert "database_url" not in data


def test_11_http_malformed_token_returns_401(client: ASGIHttpClient):
    """11. Chuỗi token bị lỗi format (không phải chuẩn JWT base64) → HTTP 401 (code TOKEN_INVALID)."""
    malformed_tokens = [
        "not-a-jwt",
        "header.payload",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.corrupted",
    ]
    for bad_token in malformed_tokens:
        response = client.get(
            "/api/v1/admin/auth/me",
            headers={"Authorization": f"Bearer {bad_token}"},
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "TOKEN_INVALID"


def test_12_http_dependency_overrides_properly_cleaned_up():
    """12. Đảm bảo app.dependency_overrides được dọn dẹp sạch sẽ sau test."""
    assert len(app.dependency_overrides) == 0
