"""
Bộ kiểm thử đơn vị cho Accounting Router & Endpoints (Phase 0B & Giai đoạn 1).
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

Kiểm thử độc lập với SQLite in-memory, không yêu cầu MariaDB thật.
"""

from datetime import datetime, timedelta
from pathlib import Path
import sys
from typing import Generator

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.main import app, dashboard
from app.models.radius import Nas, RadAcct, RadCheck, RadPostAuth
from app.routers.accounting import (
    get_accounting_session_by_id,
    get_accounting_sessions,
    get_accounting_session_trend,
    get_accounting_statistics,
    get_auth_logs,
    get_dashboard_summary,
    get_online_sessions,
)


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
