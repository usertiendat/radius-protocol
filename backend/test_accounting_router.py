"""
Bộ kiểm thử đơn vị & bảo mật cho Accounting Router & Endpoints (Phase 0B & Giai đoạn 1).
Kiểm tra tính đúng đắn của:
1. Endpoint GET /api/v1/accounting/sessions
2. Endpoint GET /api/v1/accounting/sessions/online
3. Endpoint GET /api/v1/accounting/sessions/{session_id} (thành công 200 và 404 khi không tồn tại)
4. Endpoint GET /api/v1/accounting/statistics
5. Endpoint GET /api/v1/accounting/session-trend
6. Endpoint GET /api/v1/logs/authentication & GET /api/v1/monitoring/logs
7. Endpoint GET /api/v1/dashboard/summary
8. Endpoint GET / và GET /dashboard (phục vụ dashboard.html)
9. Bảo toàn các routes trên FastAPI app.
10. Kiểm tra bảo vệ RBAC & Authentication:
    - Không có JWT -> HTTP 401 UNAUTHORIZED
    - Sai chữ ký / Token không hợp lệ -> HTTP 401 TOKEN_INVALID
    - Token hết hạn -> HTTP 401 TOKEN_EXPIRED
    - Admin bị vô hiệu hóa is_active=False -> HTTP 403 ACCOUNT_INACTIVE
    - Cả 3 vai trò (superadmin, it_admin, auditor) đều có quyền đọc Accounting.

Kiểm thử độc lập với SQLite in-memory, không yêu cầu MariaDB thật.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Dict, Generator, Optional

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import HTTPException, Request
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
from app.main import app, dashboard
from app.models import AppAdmin
from app.models.radius import Nas, RadAcct, RadCheck, RadPostAuth
from app.routers.accounting import (
    get_accounting_session_by_id,
    get_accounting_sessions,
    get_accounting_session_trend,
    get_accounting_statistics,
    get_auth_logs,
    get_dashboard_summary,
    get_online_sessions,
    require_accounting_read,
)
from app.services.admin_token import AdminTokenService

TEST_SECRET_KEY = "test-jwt-secret-key-32-chars-long-for-safe-unit-testing"
ANOTHER_SECRET_KEY = "another-wrong-secret-key-for-testing-signatures-32c"


def make_request(headers: Optional[Dict[str, str]] = None, path: str = "/api/v1/accounting/sessions", method: str = "GET") -> Request:
    raw_headers = []
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": raw_headers,
        "query_string": b"",
    }
    return Request(scope)


@pytest.fixture
def sqlite_db() -> Generator[Session, None, None]:
    """Tạo database SQLite in-memory với dữ liệu kiểm thử."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSession()

    now = datetime.now()
    session.add_all([
        AppAdmin(
            id=1,
            username="super_user",
            password_hash=hash_password("SuperSecretPass123!"),
            email="super@enterprise.local",
            role=AdminRole.SUPERADMIN.value,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        ),
        AppAdmin(
            id=2,
            username="it_user",
            password_hash=hash_password("ItSecretPass123!"),
            email="it@enterprise.local",
            role=AdminRole.IT_ADMIN.value,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        ),
        AppAdmin(
            id=3,
            username="auditor_user",
            password_hash=hash_password("AuditSecretPass123!"),
            email="audit@enterprise.local",
            role=AdminRole.AUDITOR.value,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        ),
        AppAdmin(
            id=4,
            username="inactive_user",
            password_hash=hash_password("InactivePass123!"),
            email="inactive@enterprise.local",
            role=AdminRole.AUDITOR.value,
            is_active=False,
            created_at=datetime.now(timezone.utc),
        ),
        RadAcct(
            radacctid=101,
            acctsessionid="s-101",
            acctuniqueid="u-101",
            username="alice",
            nasipaddress="192.168.1.10",
            framedipaddress="10.0.0.50",
            acctstarttime=now - timedelta(hours=2),
            acctstoptime=now - timedelta(hours=1),
            acctsessiontime=3600,
            acctinputoctets=1000,
            acctoutputoctets=2000,
            acctterminatecause="User-Request",
        ),
        RadAcct(
            radacctid=102,
            acctsessionid="s-102",
            acctuniqueid="u-102",
            username="bob",
            nasipaddress="192.168.1.11",
            framedipaddress="10.0.0.51",
            acctstarttime=now - timedelta(minutes=20),
            acctstoptime=None,  # Online
            acctsessiontime=1200,
            acctinputoctets=500,
            acctoutputoctets=1500,
            acctterminatecause="",
        ),
        RadPostAuth(
            id=1,
            username="alice",
            pass_="alice_pass_secret",
            reply="Access-Accept",
            authdate=now,
        ),
        RadPostAuth(
            id=2,
            username="mallory",
            pass_="mallory_pass_secret",
            reply="Access-Reject",
            authdate=now,
        ),
        RadCheck(id=1, username="alice", attribute="Cleartext-Password", op=":=", value="P1"),
        RadCheck(id=2, username="bob", attribute="Cleartext-Password", op=":=", value="P2"),
        Nas(id=1, nasname="192.168.1.10", secret="TopSecretNas1"),
    ])
    session.commit()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def token_service() -> AdminTokenService:
    return AdminTokenService(secret_key=TEST_SECRET_KEY)


# =============================================================================
# ENDPOINT TESTS
# =============================================================================

def test_endpoint_get_accounting_sessions(sqlite_db: Session):
    """Kiểm tra gọi endpoint get_accounting_sessions."""
    res = get_accounting_sessions(skip=0, limit=50, db=sqlite_db)
    assert isinstance(res, list)
    assert len(res) == 2
    assert res[0]["radacctid"] in (101, 102)


def test_endpoint_get_online_sessions(sqlite_db: Session):
    """Kiểm tra gọi endpoint get_online_sessions chỉ trả về phiên active."""
    res = get_online_sessions(limit=50, db=sqlite_db)
    assert isinstance(res, list)
    assert len(res) == 1
    assert res[0]["radacctid"] == 102
    assert res[0]["username"] == "bob"


def test_endpoint_get_session_by_id_success(sqlite_db: Session):
    """Kiểm tra get_accounting_session_by_id khi session tồn tại."""
    res = get_accounting_session_by_id(session_id=101, db=sqlite_db)
    assert res["radacctid"] == 101
    assert res["username"] == "alice"


def test_endpoint_get_session_by_id_404(sqlite_db: Session):
    """Kiểm tra get_accounting_session_by_id ném HTTPException 404 khi không tìm thấy."""
    with pytest.raises(HTTPException) as exc_info:
        get_accounting_session_by_id(session_id=99999, db=sqlite_db)
    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Session not found"


def test_endpoint_get_accounting_statistics(sqlite_db: Session):
    """Kiểm tra get_accounting_statistics tính toán đầy đủ chỉ số."""
    res = get_accounting_statistics(db=sqlite_db)
    assert res["active_sessions"] == 1
    assert res["total_duration"] == 3600 + 1200
    assert res["total_download_bytes"] == 1000 + 500
    assert res["total_upload_bytes"] == 2000 + 1500


def test_endpoint_get_session_trend(sqlite_db: Session):
    """Kiểm tra get_accounting_session_trend trả về thống kê theo ngày."""
    res = get_accounting_session_trend(days=7, db=sqlite_db)
    assert isinstance(res, list)
    assert len(res) == 7
    assert all("date" in d and "sessions" in d for d in res)


def test_endpoint_get_auth_logs(sqlite_db: Session):
    """Kiểm tra get_auth_logs trả về nhật ký và không chứa pass."""
    res = get_auth_logs(skip=0, limit=50, db=sqlite_db)
    assert len(res) == 2
    for log in res:
        assert "pass" not in log
        assert "pass_" not in log


def test_endpoint_get_dashboard_summary(sqlite_db: Session):
    """Kiểm tra get_dashboard_summary tổng hợp đúng chỉ số."""
    res = get_dashboard_summary(db=sqlite_db)
    assert res["total_users"] == 2
    assert res["total_nas"] == 1
    assert res["active_sessions"] == 1
    assert res["login_success_today"] == 1
    assert res["login_failed_today"] == 1


def test_dashboard_endpoint_callable():
    """Kiểm tra endpoint phục vụ file dashboard.html có thể gọi và trả về FileResponse."""
    resp = dashboard()
    assert resp.status_code == 200
    assert "dashboard.html" in str(resp.path)


def test_routes_registered_in_fastapi_app():
    """Kiểm tra tất cả accounting routes được đăng ký chuẩn trong app."""
    paths = set()
    for r in app.routes:
        if hasattr(r, "path"):
            paths.add(r.path)
        elif hasattr(r, "original_router"):
            for sub_r in r.original_router.routes:
                paths.add(sub_r.path)

    assert "/api/v1/accounting/sessions" in paths
    assert "/api/v1/accounting/sessions/online" in paths
    assert "/api/v1/accounting/sessions/{session_id}" in paths
    assert "/api/v1/accounting/statistics" in paths
    assert "/api/v1/accounting/session-trend" in paths
    assert "/api/v1/logs/authentication" in paths
    assert "/api/v1/monitoring/logs" in paths
    assert "/api/v1/dashboard/summary" in paths
    assert "/" in paths
    assert "/dashboard" in paths


# =============================================================================
# AUTHENTICATION & RBAC TESTS CHO ACCOUNTING
# =============================================================================

def test_missing_jwt_raises_unauthorized(sqlite_db: Session, token_service: AdminTokenService):
    """Không có Authorization header -> HTTP 401 Unauthorized."""
    req = make_request()
    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(request=req, credentials=None, db=sqlite_db, token_service=token_service)
    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "UNAUTHORIZED"


def test_invalid_jwt_signature_raises_unauthorized(sqlite_db: Session):
    """JWT có chữ ký sai / secret key khác -> HTTP 401 Unauthorized."""
    wrong_service = AdminTokenService(secret_key=ANOTHER_SECRET_KEY)
    token = wrong_service.create_access_token(sub="1", role="superadmin")
    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    real_service = AdminTokenService(secret_key=TEST_SECRET_KEY)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(request=req, credentials=creds, db=sqlite_db, token_service=real_service)
    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "TOKEN_INVALID"


def test_expired_jwt_raises_unauthorized(sqlite_db: Session, token_service: AdminTokenService):
    """JWT đã hết hạn -> HTTP 401 Unauthorized."""
    token = token_service.create_access_token(sub="1", role="superadmin", expires_delta=timedelta(seconds=-10))
    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(UnauthorizedError) as exc_info:
        get_current_admin(request=req, credentials=creds, db=sqlite_db, token_service=token_service)
    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "TOKEN_EXPIRED"


def test_inactive_admin_raises_forbidden(sqlite_db: Session, token_service: AdminTokenService):
    """Admin bị vô hiệu hóa is_active=False -> HTTP 403 ACCOUNT_INACTIVE."""
    token = token_service.create_access_token(sub="4", role=AdminRole.AUDITOR.value)
    req = make_request(headers={"Authorization": f"Bearer {token}"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    with pytest.raises(ForbiddenError) as exc_info:
        get_current_admin(request=req, credentials=creds, db=sqlite_db, token_service=token_service)
    assert exc_info.value.http_status == 403
    assert exc_info.value.code == "ACCOUNT_INACTIVE"


def test_all_three_roles_granted_accounting_read():
    """Cả 3 vai trò (superadmin, it_admin, auditor) đều có quyền đọc Accounting/Monitoring."""
    super_admin = CurrentAdmin(id=1, username="super", email="s@e.l", role=AdminRole.SUPERADMIN.value, is_active=True)
    it_admin = CurrentAdmin(id=2, username="it", email="i@e.l", role=AdminRole.IT_ADMIN.value, is_active=True)
    auditor = CurrentAdmin(id=3, username="audit", email="a@e.l", role=AdminRole.AUDITOR.value, is_active=True)

    assert require_accounting_read(current_admin=super_admin) is super_admin
    assert require_accounting_read(current_admin=it_admin) is it_admin
    assert require_accounting_read(current_admin=auditor) is auditor


def test_endpoints_with_authorized_admin(sqlite_db: Session):
    """Kiểm tra các endpoints Accounting hoạt động chuẩn xác khi truyền admin hợp lệ."""
    admin = CurrentAdmin(id=3, username="audit", email="a@e.l", role=AdminRole.AUDITOR.value, is_active=True)

    sessions = get_accounting_sessions(skip=0, limit=10, db=sqlite_db, current_admin=admin)
    assert len(sessions) == 2

    online = get_online_sessions(limit=10, db=sqlite_db, current_admin=admin)
    assert len(online) == 1

    session_detail = get_accounting_session_by_id(session_id=101, db=sqlite_db, current_admin=admin)
    assert session_detail["radacctid"] == 101

    stats = get_accounting_statistics(db=sqlite_db, current_admin=admin)
    assert stats["active_sessions"] == 1

    trend = get_accounting_session_trend(days=3, db=sqlite_db, current_admin=admin)
    assert len(trend) == 3

    auth_logs = get_auth_logs(skip=0, limit=10, db=sqlite_db, current_admin=admin)
    assert len(auth_logs) == 2

    summary = get_dashboard_summary(db=sqlite_db, current_admin=admin)
    assert summary["total_users"] == 2
