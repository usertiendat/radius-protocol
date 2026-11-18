"""
HTTP Integration Tests cho Admin Password Change API (POST /api/v1/admin/auth/change-password) (Phase 0B - Step 1.1).
Thực hiện HTTP requests thực sự qua FastAPI ASGI pipeline sử dụng Async-Native testing với httpx.AsyncClient và httpx.ASGITransport.

Pipeline được kiểm thử toàn diện:
1. HTTP routing (/api/v1/admin/auth/change-password)
2. Authentication dependency (HTTPBearer + get_current_admin)
3. JWT validation (AdminTokenService: signature, expiry, claims)
4. Current Admin resolution (AppAdmin lookup, is_active verification)
5. Request schema validation (AdminChangePasswordRequest Pydantic validation)
6. Password Change Handler (change_password router handler)
7. AdminAuthService (transactional boundary, timing attack defense, PBKDF2 hashing)
8. Database interaction (SQLAlchemy AppAdmin model, SQLite in-memory StaticPool)
9. Global exception handling (BaseBusinessException -> JSONResponse, 401, 403, 422)
10. HTTP response mapping (AdminChangePasswordResponse serialization)

Tuân thủ nghiêm ngặt các tiêu chuẩn kiến trúc và bảo mật:
- Hoàn toàn Async-Native, KHÔNG sử dụng bất kỳ global monkeypatch nào đối với asyncio, AnyIO hay Starlette.
- Cơ chế Dependency Overrides Snapshot & Restore bảo đảm khôi phục 100% trạng thái ban đầu kể cả khi khởi tạo lỗi hoặc test fail.
- Fixture async_client và test kiểm tra chia sẻ chung cơ chế admin_auth_dependency_scope có thể kiểm chứng trực tiếp.
- Tuyệt đối KHÔNG override get_current_admin để kiểm tra authentication dependency thực tế.
- Chỉ override get_db và get_admin_token_service.
- Cô lập hoàn toàn với SQLite in-memory, không kết nối MariaDB thật.
"""

from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Any, AsyncGenerator, Generator, Optional

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import httpx
import jwt
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Import theo thứ tự an toàn tránh circular import
from app.core.admin_dependencies import get_admin_token_service, get_current_admin
from app.core.security import hash_password, verify_password
from app.database import Base, get_db
from app.main import app
from app.models.application import AppAdmin
from app.services.admin_token import AdminTokenService

TEST_SECRET_KEY = "test-jwt-secret-key-32-chars-long-for-safe-unit-testing"
ANOTHER_SECRET_KEY = "another-wrong-secret-key-for-testing-signatures-32c"
ENDPOINT_CHANGE_PASSWORD = "/api/v1/admin/auth/change-password"

INITIAL_SUPERADMIN_PASSWORD = "CurrentSecurePass123!"
INITIAL_DISABLED_PASSWORD = "DisabledPass123!"


@pytest.fixture
def anyio_backend():
    """Chỉ định backend asyncio cho AnyIO pytest runner."""
    return "asyncio"


@dataclass
class DatabaseFixture:
    """Cấu trúc dữ liệu đại diện cho fixture CSDL SQLite in-memory cô lập."""
    engine: Any
    session_factory: Any
    active_admin_id: int
    disabled_admin_id: int


@pytest.fixture
def test_db() -> Generator[DatabaseFixture, None, None]:
    """Khởi tạo SQLite in-memory database cô lập với StaticPool cho từng test case."""
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

    seed_session = TestingSession()
    try:
        active_admin = AppAdmin(
            id=1,
            username="super_admin",
            password_hash=hash_password(INITIAL_SUPERADMIN_PASSWORD),
            email="admin@enterprise.local",
            role="superadmin",
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        disabled_admin = AppAdmin(
            id=2,
            username="disabled_admin",
            password_hash=hash_password(INITIAL_DISABLED_PASSWORD),
            email="disabled@enterprise.local",
            role="auditor",
            is_active=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        seed_session.add(active_admin)
        seed_session.add(disabled_admin)
        seed_session.commit()
    finally:
        seed_session.close()

    fixture_obj = DatabaseFixture(
        engine=engine,
        session_factory=TestingSession,
        active_admin_id=1,
        disabled_admin_id=2,
    )
    try:
        yield fixture_obj
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def test_token_service() -> AdminTokenService:
    """Cung cấp AdminTokenService dùng riêng cho test suite với secret key cô lập."""
    return AdminTokenService(secret_key=TEST_SECRET_KEY)


@asynccontextmanager
async def admin_auth_dependency_scope(
    db_factory: Any,
    token_service: AdminTokenService,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """
    Context manager dùng chung cho cả fixture async_client và kiểm thử độc lập:
    - Lưu snapshot ban đầu của app.dependency_overrides trước khi thiết lập bất kỳ override nào.
    - Chỉ thiết lập đúng 2 overrides: get_db và get_admin_token_service.
    - Tuyệt đối KHÔNG override get_current_admin.
    - Bọc toàn bộ quá trình thiết lập overrides, tạo client và đóng client trong try/finally.
    - Đảm bảo khối finally luôn khôi phục 100% snapshot ban đầu trong mọi tình huống (kể cả khi khởi tạo lỗi hoặc có exception).
    """
    original_overrides = dict(app.dependency_overrides)

    def override_get_db() -> Generator[Session, None, None]:
        db = db_factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def override_token_service() -> AdminTokenService:
        return token_service

    try:
        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_admin_token_service] = override_token_service

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)


@pytest.fixture
async def async_client(
    test_db: DatabaseFixture,
    test_token_service: AdminTokenService,
    anyio_backend: str,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """
    Thiết lập Async HTTP Client qua ASGI Application kèm dependency overrides snapshot/restore.
    Sử dụng chung cơ chế admin_auth_dependency_scope.
    """
    async with admin_auth_dependency_scope(
        db_factory=test_db.session_factory,
        token_service=test_token_service,
    ) as client:
        yield client


@pytest.fixture
def active_admin_token(test_db: DatabaseFixture, test_token_service: AdminTokenService) -> str:
    """Tạo Access Token hợp lệ cho active super_admin."""
    return test_token_service.create_access_token(
        sub=str(test_db.active_admin_id),
        role="superadmin",
    )


def _get_admin_from_db(test_db: DatabaseFixture, admin_id: int) -> Optional[AppAdmin]:
    """Truy vấn bản ghi AppAdmin trực tiếp từ database bằng session độc lập."""
    session = test_db.session_factory()
    try:
        return session.query(AppAdmin).filter(AppAdmin.id == admin_id).first()
    finally:
        session.close()


# =============================================================================
# NHÓM A: AUTHENTICATION VÀ JWT VALIDATION
# =============================================================================

@pytest.mark.anyio
async def test_01_http_valid_jwt_and_correct_password_returns_200(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """1. Token hợp lệ và mật khẩu hiện tại chính xác → HTTP 200 OK."""
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Đổi mật khẩu thành công."
    assert "admin" in data
    assert data["admin"]["id"] == 1
    assert data["admin"]["username"] == "super_admin"
    assert data["admin"]["role"] == "superadmin"
    assert data["admin"]["is_active"] is True


@pytest.mark.anyio
async def test_02_http_missing_authorization_header_returns_401(async_client: httpx.AsyncClient):
    """2. Không có Authorization header → HTTP 401 Unauthorized (code UNAUTHORIZED)."""
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
    )

    assert response.status_code == 401
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "UNAUTHORIZED"
    assert "Authorization" in data["error"]["message"]


@pytest.mark.anyio
async def test_03_http_wrong_authorization_scheme_returns_401(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """3. Authorization scheme không phải Bearer (Basic, Token) → HTTP 401 (code TOKEN_INVALID)."""
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }

    # Thử scheme Basic
    res_basic = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Basic {active_admin_token}"},
    )
    assert res_basic.status_code == 401
    assert res_basic.json()["error"]["code"] == "TOKEN_INVALID"

    # Thử scheme Token
    res_token = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Token {active_admin_token}"},
    )
    assert res_token.status_code == 401
    assert res_token.json()["error"]["code"] == "TOKEN_INVALID"


@pytest.mark.anyio
async def test_04_http_wrong_jwt_signature_returns_401(
    async_client: httpx.AsyncClient,
    test_db: DatabaseFixture,
):
    """4. JWT sai chữ ký (ký bằng khóa bí mật khác) → HTTP 401 Unauthorized (code TOKEN_INVALID)."""
    other_token_service = AdminTokenService(secret_key=ANOTHER_SECRET_KEY)
    tampered_token = other_token_service.create_access_token(
        sub=str(test_db.active_admin_id),
        role="superadmin",
    )

    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {tampered_token}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "TOKEN_INVALID"


@pytest.mark.anyio
async def test_05_http_expired_jwt_returns_401(
    async_client: httpx.AsyncClient,
    test_token_service: AdminTokenService,
    test_db: DatabaseFixture,
):
    """5. JWT hết hạn → HTTP 401 Unauthorized (code TOKEN_EXPIRED)."""
    expired_token = test_token_service.create_access_token(
        sub=str(test_db.active_admin_id),
        role="superadmin",
        expires_delta=timedelta(minutes=-15),
    )

    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {expired_token}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "TOKEN_EXPIRED"
    assert "hết hạn" in data["error"]["message"].lower()


@pytest.mark.anyio
async def test_06_http_wrong_jwt_token_type_returns_401(async_client: httpx.AsyncClient):
    """6. JWT có token type không hợp lệ (ví dụ type='refresh') → HTTP 401 (code TOKEN_INVALID)."""
    now = datetime.now(timezone.utc)
    payload_refresh = {
        "sub": "1",
        "role": "superadmin",
        "type": "refresh",  # Không phải 'access'
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    refresh_token = jwt.encode(payload_refresh, TEST_SECRET_KEY, algorithm="HS256")

    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {refresh_token}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "TOKEN_INVALID"


@pytest.mark.anyio
async def test_07_http_non_existent_admin_returns_401(
    async_client: httpx.AsyncClient,
    test_token_service: AdminTokenService,
):
    """7. Admin không còn tồn tại trong CSDL → HTTP 401 (code TOKEN_INVALID theo contract hiện tại)."""
    ghost_token = test_token_service.create_access_token(
        sub="99999",
        role="superadmin",
    )

    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {ghost_token}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "TOKEN_INVALID"
    assert "không tồn tại" in data["error"]["message"].lower()


@pytest.mark.anyio
async def test_08_http_inactive_admin_returns_403(
    async_client: httpx.AsyncClient,
    test_db: DatabaseFixture,
    test_token_service: AdminTokenService,
):
    """8. Admin inactive (is_active=False) → HTTP 403 Forbidden (code ACCOUNT_INACTIVE)."""
    disabled_token = test_token_service.create_access_token(
        sub=str(test_db.disabled_admin_id),
        role="auditor",
    )

    payload = {
        "current_password": INITIAL_DISABLED_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {disabled_token}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert data["error"]["code"] == "ACCOUNT_INACTIVE"
    assert "vô hiệu hóa" in data["error"]["message"].lower()


# =============================================================================
# NHÓM B: PASSWORD CHANGE BUSINESS LOGIC
# =============================================================================

@pytest.mark.anyio
async def test_09_http_incorrect_current_password_returns_401(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
    test_db: DatabaseFixture,
):
    """9. Mật khẩu hiện tại không chính xác → HTTP 401 (code INVALID_CREDENTIALS)."""
    payload = {
        "current_password": "WrongCurrentPassword999!",
        "new_password": "BrandNewValidPass456!",
        "confirm_password": "BrandNewValidPass456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "INVALID_CREDENTIALS"
    assert "Mật khẩu hiện tại không chính xác" in data["error"]["message"]

    # Đảm bảo mật khẩu trong CSDL không bị thay đổi
    admin = _get_admin_from_db(test_db, test_db.active_admin_id)
    assert admin is not None
    assert verify_password(INITIAL_SUPERADMIN_PASSWORD, admin.password_hash) is True
    assert verify_password("BrandNewValidPass456!", admin.password_hash) is False


@pytest.mark.anyio
async def test_10_http_new_password_same_as_current_returns_422(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
    test_db: DatabaseFixture,
):
    """10. Mật khẩu mới trùng mật khẩu hiện tại → HTTP 422 (code PASSWORD_REUSED)."""
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": INITIAL_SUPERADMIN_PASSWORD,
        "confirm_password": INITIAL_SUPERADMIN_PASSWORD,
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )

    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "PASSWORD_REUSED"
    assert "trùng" in data["error"]["message"].lower()

    # Đảm bảo mật khẩu trong CSDL không bị thay đổi
    admin = _get_admin_from_db(test_db, test_db.active_admin_id)
    assert admin is not None
    assert verify_password(INITIAL_SUPERADMIN_PASSWORD, admin.password_hash) is True


@pytest.mark.anyio
@pytest.mark.parametrize("short_pass", ["1234567", "short", "a", ""])
async def test_11_http_new_password_shorter_than_minimum_returns_422(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
    short_pass: str,
):
    """11. Mật khẩu mới ngắn hơn giới hạn (<8 ký tự) → HTTP 422 Unprocessable Entity."""
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": short_pass,
        "confirm_password": short_pass,
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_12_http_new_password_longer_than_maximum_returns_422(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """12. Mật khẩu mới dài hơn giới hạn (>128 ký tự) → HTTP 422 Unprocessable Entity."""
    overlong_pass = "A" * 129
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": overlong_pass,
        "confirm_password": overlong_pass,
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_13_http_confirm_password_mismatch_returns_422(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """13. Confirm password không khớp → HTTP 422 Unprocessable Entity."""
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword123!",
        "confirm_password": "DifferentConfirmPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )

    assert response.status_code == 422


@pytest.mark.anyio
@pytest.mark.parametrize(
    "missing_payload",
    [
        {"new_password": "NewPass123!", "confirm_password": "NewPass123!"},  # thiếu current_password
        {"current_password": INITIAL_SUPERADMIN_PASSWORD, "confirm_password": "NewPass123!"},  # thiếu new_password
        {"current_password": INITIAL_SUPERADMIN_PASSWORD, "new_password": "NewPass123!"},  # thiếu confirm_password
        {},  # thiếu toàn bộ
    ],
)
async def test_14_http_missing_required_fields_returns_422(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
    missing_payload: dict,
):
    """14. Thiếu trường bắt buộc → HTTP 422 Unprocessable Entity."""
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=missing_payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )

    assert response.status_code == 422


@pytest.mark.anyio
async def test_15_http_malformed_request_body_returns_422(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """15. Request body sai định dạng (không phải JSON hợp lệ hoặc sai kiểu dữ liệu) → HTTP 422."""
    # Body không phải JSON hợp lệ
    res_malformed_json = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        content="{not a valid json string...",
        headers={
            "Authorization": f"Bearer {active_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert res_malformed_json.status_code == 422

    # Kiểu dữ liệu không phải string
    res_wrong_types = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json={
            "current_password": 12345678,
            "new_password": True,
            "confirm_password": ["an", "array"],
        },
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )
    assert res_wrong_types.status_code == 422


# =============================================================================
# NHÓM C: SUCCESSFUL PASSWORD CHANGE & DATA INTEGRITY
# =============================================================================

@pytest.mark.anyio
async def test_16_http_successful_password_change_returns_200(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """16. Đổi mật khẩu thành công → HTTP 200 OK với đầy đủ thông điệp và DTO an toàn."""
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "BrandNewSecurePassword789!",
        "confirm_password": "BrandNewSecurePassword789!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Đổi mật khẩu thành công."
    assert "admin" in data
    assert data["admin"]["id"] == 1
    assert data["admin"]["username"] == "super_admin"
    assert data["admin"]["email"] == "admin@enterprise.local"
    assert data["admin"]["role"] == "superadmin"
    assert data["admin"]["is_active"] is True
    assert "created_at" in data["admin"]


@pytest.mark.anyio
async def test_17_http_old_password_no_longer_verifies(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
    test_db: DatabaseFixture,
):
    """17. Sau khi đổi thành công, mật khẩu cũ không còn xác thực được."""
    new_password = "BrandNewSecurePassword789!"
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": new_password,
        "confirm_password": new_password,
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )
    assert response.status_code == 200

    admin_in_db = _get_admin_from_db(test_db, test_db.active_admin_id)
    assert admin_in_db is not None
    # Mật khẩu cũ không còn khớp
    assert verify_password(INITIAL_SUPERADMIN_PASSWORD, admin_in_db.password_hash) is False


@pytest.mark.anyio
async def test_18_http_new_password_verifies_successfully(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
    test_db: DatabaseFixture,
):
    """18. Sau khi đổi thành công, mật khẩu mới xác thực được chính xác."""
    new_password = "BrandNewSecurePassword789!"
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": new_password,
        "confirm_password": new_password,
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )
    assert response.status_code == 200

    admin_in_db = _get_admin_from_db(test_db, test_db.active_admin_id)
    assert admin_in_db is not None
    # Mật khẩu mới xác thực thành công
    assert verify_password(new_password, admin_in_db.password_hash) is True


@pytest.mark.anyio
async def test_19_http_admin_fields_outside_password_preserved(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
    test_db: DatabaseFixture,
):
    """19. Không thay đổi thông tin Admin ngoài những trường được thiết kế (chỉ đổi password_hash và updated_at)."""
    admin_before = _get_admin_from_db(test_db, test_db.active_admin_id)
    assert admin_before is not None
    before_id = admin_before.id
    before_username = admin_before.username
    before_email = admin_before.email
    before_role = admin_before.role
    before_is_active = admin_before.is_active
    before_created_at = admin_before.created_at
    before_updated_at = admin_before.updated_at
    before_hash = admin_before.password_hash

    new_password = "BrandNewSecurePassword789!"
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": new_password,
        "confirm_password": new_password,
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )
    assert response.status_code == 200

    admin_after = _get_admin_from_db(test_db, test_db.active_admin_id)
    assert admin_after is not None

    # Các trường bắt buộc giữ nguyên tuyệt đối
    assert admin_after.id == before_id
    assert admin_after.username == before_username
    assert admin_after.email == before_email
    assert admin_after.role == before_role
    assert admin_after.is_active == before_is_active
    assert admin_after.created_at == before_created_at

    # Các trường được phép thay đổi
    assert admin_after.password_hash != before_hash
    assert admin_after.updated_at is not None
    if before_updated_at is not None:
        assert admin_after.updated_at >= before_updated_at


@pytest.mark.anyio
async def test_20_http_data_persisted_correctly_after_transaction_commit(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
    test_db: DatabaseFixture,
):
    """20. Kiểm tra dữ liệu được lưu đúng và bền vững sau khi transaction hoàn tất (query từ Session hoàn toàn mới)."""
    new_password = "PersistedStrongPassword999!"
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": new_password,
        "confirm_password": new_password,
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )
    assert response.status_code == 200

    # Khởi tạo một Session hoàn toàn mới độc lập từ Session Factory để kiểm tra dữ liệu đã commit
    fresh_session = test_db.session_factory()
    try:
        persisted_admin = fresh_session.query(AppAdmin).filter(AppAdmin.id == test_db.active_admin_id).first()
        assert persisted_admin is not None
        assert persisted_admin.username == "super_admin"
        assert verify_password(new_password, persisted_admin.password_hash) is True
    finally:
        fresh_session.close()


# =============================================================================
# NHÓM D: SENSITIVE DATA PROTECTION & TEST HYGIENE
# =============================================================================

@pytest.mark.anyio
async def test_21_http_response_does_not_contain_plaintext_password(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """21. Response HTTP 200 tuyệt đối không chứa mật khẩu dạng rõ (cả cũ lẫn mới)."""
    new_password = "SecretBrandNewPass999!"
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": new_password,
        "confirm_password": new_password,
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )
    assert response.status_code == 200

    raw_response_text = response.text
    assert INITIAL_SUPERADMIN_PASSWORD not in raw_response_text
    assert new_password not in raw_response_text


@pytest.mark.anyio
async def test_22_http_response_does_not_contain_password_hash_or_salt(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """22. Response HTTP 200 tuyệt đối không chứa password hash hoặc salt."""
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )
    assert response.status_code == 200

    data = response.json()
    assert "password_hash" not in data
    assert "salt" not in data
    if "admin" in data:
        assert "password_hash" not in data["admin"]
        assert "password" not in data["admin"]
        assert "salt" not in data["admin"]

    # Rà soát raw text không chứa chuỗi thuật toán băm
    assert "pbkdf2" not in response.text.lower()


@pytest.mark.anyio
async def test_23_http_response_does_not_contain_jwt_secret(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """23. Response HTTP 200 tuyệt đối không chứa JWT secret."""
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )
    assert response.status_code == 200

    raw_text = response.text
    assert TEST_SECRET_KEY not in raw_text
    assert "secret" not in response.json()
    assert "secret_key" not in response.json()


@pytest.mark.anyio
async def test_24_http_response_does_not_contain_internal_infrastructure_details(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """24. Response không chứa thông tin hạ tầng nội bộ (database URL, SQL query, stack trace)."""
    payload = {
        "current_password": INITIAL_SUPERADMIN_PASSWORD,
        "new_password": "NewValidPassword456!",
        "confirm_password": "NewValidPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )
    assert response.status_code == 200

    raw_text = response.text.lower()
    assert "database" not in raw_text
    assert "sqlalchemy" not in raw_text
    assert "traceback" not in raw_text
    assert "select" not in raw_text


@pytest.mark.anyio
async def test_25_http_error_response_does_not_leak_submitted_passwords(
    async_client: httpx.AsyncClient,
    active_admin_token: str,
):
    """25. Response lỗi (401, 422) tuyệt đối không phản xạ lại mật khẩu người dùng đã nhập."""
    sensitive_attempt = "MySuperSecretWrongPass!"
    payload = {
        "current_password": sensitive_attempt,
        "new_password": "ValidNewPassword456!",
        "confirm_password": "ValidNewPassword456!",
    }
    response = await async_client.post(
        ENDPOINT_CHANGE_PASSWORD,
        json=payload,
        headers={"Authorization": f"Bearer {active_admin_token}"},
    )
    assert response.status_code == 401

    # Kiểm tra raw response text không phản xạ lại mật khẩu
    assert sensitive_attempt not in response.text


@pytest.mark.anyio
async def test_26_http_dependency_overrides_snapshot_restore_verified(
    test_db: DatabaseFixture,
    test_token_service: AdminTokenService,
):
    """
    26. Xác minh trực tiếp cơ chế snapshot/restore của admin_auth_dependency_scope (dùng chung với fixture):
    - Bảo đảm cleanup của test_26 luôn được thực thi bằng try/finally toàn cục bao bọc toàn bộ kiểm thử.
    - Baseline overrides được bảo toàn nguyên vẹn sau cleanup.
    - Hai override get_db và get_admin_token_service được thiết lập đúng và gỡ đúng.
    - Snapshot preservation đối với get_current_admin: không giả định trạng thái ban đầu,
      xác minh scope không tự ý thay đổi hoặc thêm override cho get_current_admin.
    - Sử dụng pytest.raises(RuntimeError) để kiểm tra exception propagation và phục hồi snapshot khi có lỗi.
    - Không để lại dummy override hoặc side effect sau khi test kết thúc.
    """
    # Lưu trạng thái overrides ban đầu trước mọi thao tác
    prior_overrides = dict(app.dependency_overrides)

    def dummy_dependency():
        return "original_value"

    dummy_override_val = "baseline_mock_value"

    try:
        # 1. Thiết lập một baseline override giả lập trước khi scope hoạt động
        app.dependency_overrides[dummy_dependency] = lambda: dummy_override_val
        snapshot_before = dict(app.dependency_overrides)
        assert dummy_dependency in snapshot_before

        # Ghi nhận trạng thái ban đầu của get_current_admin (không giả định tồn tại hay không)
        initial_get_current_admin = snapshot_before.get(get_current_admin)

        # 2. Kiểm tra chu trình hoạt động bình thường qua admin_auth_dependency_scope
        async with admin_auth_dependency_scope(
            db_factory=test_db.session_factory,
            token_service=test_token_service,
        ) as client:
            # Hai override của Step 1.1 được chủ động thiết lập
            assert get_db in app.dependency_overrides
            assert get_admin_token_service in app.dependency_overrides
            # Scope tuyệt đối không tự ý thay đổi hay thêm override cho get_current_admin
            assert app.dependency_overrides.get(get_current_admin) == initial_get_current_admin
            # Baseline override vẫn được bảo toàn trong suốt quá trình
            assert app.dependency_overrides[dummy_dependency]() == dummy_override_val
            # Xác nhận client hoạt động bình thường qua ASGI request
            res = await client.get("/health")
            assert res.status_code == 200

        # 3. Xác minh sau khi thoát scope bình thường: khớp 100% với snapshot_before
        assert app.dependency_overrides == snapshot_before
        assert get_db not in app.dependency_overrides or snapshot_before.get(get_db) == app.dependency_overrides.get(get_db)
        assert get_admin_token_service not in app.dependency_overrides or snapshot_before.get(get_admin_token_service) == app.dependency_overrides.get(get_admin_token_service)
        assert app.dependency_overrides.get(get_current_admin) == initial_get_current_admin
        assert app.dependency_overrides[dummy_dependency]() == dummy_override_val

        # 4. Kiểm tra khi có exception phát sinh bên trong scope:
        # Sử dụng pytest.raises(RuntimeError) để xác minh exception được truyền ra ngoài đúng dự kiến
        with pytest.raises(RuntimeError, match="Simulated failure inside test body"):
            async with admin_auth_dependency_scope(
                db_factory=test_db.session_factory,
                token_service=test_token_service,
            ):
                assert get_db in app.dependency_overrides
                assert get_admin_token_service in app.dependency_overrides
                assert app.dependency_overrides.get(get_current_admin) == initial_get_current_admin
                raise RuntimeError("Simulated failure inside test body")

        # 5. Xác minh sau khi có exception: snapshot vẫn được phục hồi trọn vẹn
        assert app.dependency_overrides == snapshot_before
        assert get_db not in app.dependency_overrides or snapshot_before.get(get_db) == app.dependency_overrides.get(get_db)
        assert get_admin_token_service not in app.dependency_overrides or snapshot_before.get(get_admin_token_service) == app.dependency_overrides.get(get_admin_token_service)
        assert app.dependency_overrides.get(get_current_admin) == initial_get_current_admin
        assert app.dependency_overrides[dummy_dependency]() == dummy_override_val

    finally:
        # Khôi phục chính xác trạng thái prior_overrides ban đầu, không để rò rỉ bất kỳ dummy override nào
        app.dependency_overrides.clear()
        app.dependency_overrides.update(prior_overrides)
        assert dummy_dependency not in app.dependency_overrides
