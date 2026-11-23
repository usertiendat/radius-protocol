"""
Bộ kiểm thử đơn vị cho Accounting Service (Phase 0B & Giai đoạn 1).
Kiểm tra tính đúng đắn của:
1. AccountingService ORM mapping trên các bảng FreeRADIUS (radacct, radpostauth, radcheck, nas).
2. list_sessions, get_session, list_online_sessions, get_statistics, get_session_trend, list_auth_logs, get_dashboard_summary.
3. An toàn thông tin: Tuyệt đối không để lộ radpostauth.pass hay nas.secret.
4. Xử lý trường hợp CSDL rỗng và dữ liệu biên.

Kiểm thử độc lập với SQLite in-memory, không yêu cầu MariaDB thật.
"""

from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Generator

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models.radius import Nas, RadAcct, RadCheck, RadPostAuth
from app.services.accounting_service import AccountingService


@pytest.fixture
def sqlite_session() -> Generator[Session, None, None]:
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

    now = datetime.now()
    yesterday = now - timedelta(days=1)

    # 1. Thêm bản ghi mẫu cho radacct (1 online, 2 ended)
    session.add_all([
        RadAcct(
            radacctid=1,
            acctsessionid="sess-001",
            acctuniqueid="uniq-001",
            username="user1",
            nasipaddress="192.168.1.1",
            framedipaddress="10.0.0.2",
            acctstarttime=yesterday,
            acctstoptime=yesterday + timedelta(seconds=3600),
            acctsessiontime=3600,
            acctinputoctets=1048576,  # 1MB
            acctoutputoctets=2097152,  # 2MB
            acctterminatecause="User-Request",
        ),
        RadAcct(
            radacctid=2,
            acctsessionid="sess-002",
            acctuniqueid="uniq-002",
            username="user2",
            nasipaddress="192.168.1.2",
            framedipaddress="10.0.0.3",
            acctstarttime=now - timedelta(minutes=30),
            acctstoptime=None,  # Đang online
            acctsessiontime=1800,
            acctinputoctets=524288,
            acctoutputoctets=1048576,
            acctterminatecause="",
        ),
        RadAcct(
            radacctid=3,
            acctsessionid="sess-003",
            acctuniqueid="uniq-003",
            username="user1",
            nasipaddress="192.168.1.1",
            framedipaddress="10.0.0.4",
            acctstarttime=now - timedelta(minutes=10),
            acctstoptime=now,
            acctsessiontime=600,
            acctinputoctets=256000,
            acctoutputoctets=512000,
            acctterminatecause="Admin-Reset",
        ),
    ])

    # 2. Thêm bản ghi mẫu cho radpostauth
    session.add_all([
        RadPostAuth(
            id=1,
            username="user1",
            pass_="SuperSecretPassUser1",  # Tuyệt đối không được lộ ra ngoài
            reply="Access-Accept",
            authdate=now,
        ),
        RadPostAuth(
            id=2,
            username="user2",
            pass_="WrongPassAttempt",
            reply="Access-Reject",
            authdate=now,
        ),
    ])

    # 3. Thêm bản ghi cho radcheck và nas
    session.add_all([
        RadCheck(id=1, username="user1", attribute="Cleartext-Password", op=":=", value="Secret1"),
        RadCheck(id=2, username="user2", attribute="Cleartext-Password", op=":=", value="Secret2"),
        Nas(
            id=1,
            nasname="192.168.1.1",
            shortname="AP-Floor1",
            secret="RadiusSharedSecret999",  # Tuyệt đối không được lộ ra ngoài
        ),
    ])

    session.commit()
    try:
        yield session
    finally:
        session.close()


def test_service_init_requires_valid_session():
    """Kiểm tra AccountingService bắt buộc nhận instance Session hợp lệ."""
    with pytest.raises(TypeError):
        AccountingService(None)  # type: ignore

    with pytest.raises(TypeError):
        AccountingService("not-a-session")  # type: ignore


def test_list_sessions(sqlite_session: Session):
    """Kiểm tra list_sessions sắp xếp giảm dần theo acctstarttime và hỗ trợ phân trang."""
    service = AccountingService(sqlite_session)
    sessions = service.list_sessions(skip=0, limit=10)

    assert len(sessions) == 3
    # Sắp xếp mới nhất trước
    assert sessions[0]["radacctid"] in (2, 3)
    assert "username" in sessions[0]
    assert "nasipaddress" in sessions[0]
    assert "acctstarttime" in sessions[0]
    assert "acctstoptime" in sessions[0]
    assert "acctsessiontime" in sessions[0]

    # Kiểm tra phân trang
    page_1 = service.list_sessions(skip=0, limit=2)
    assert len(page_1) == 2
    page_2 = service.list_sessions(skip=2, limit=2)
    assert len(page_2) == 1


def test_get_session_by_id_found(sqlite_session: Session):
    """Kiểm tra get_session trả về chi tiết đầy đủ khi tìm thấy radacctid."""
    service = AccountingService(sqlite_session)
    session = service.get_session(1)

    assert session is not None
    assert session["radacctid"] == 1
    assert session["username"] == "user1"
    assert session["nasipaddress"] == "192.168.1.1"
    assert session["acctsessiontime"] == 3600
    assert session["acctterminatecause"] == "User-Request"


def test_get_session_by_id_not_found(sqlite_session: Session):
    """Kiểm tra get_session trả về None khi không tồn tại radacctid."""
    service = AccountingService(sqlite_session)
    session = service.get_session(9999)
    assert session is None


def test_list_online_sessions(sqlite_session: Session):
    """Kiểm tra list_online_sessions chỉ lấy các phiên có acctstoptime IS NULL."""
    service = AccountingService(sqlite_session)
    online_sessions = service.list_online_sessions(limit=50)

    assert len(online_sessions) == 1
    assert online_sessions[0]["radacctid"] == 2
    assert online_sessions[0]["username"] == "user2"
    assert online_sessions[0]["framedipaddress"] == "10.0.0.3"


def test_get_statistics(sqlite_session: Session):
    """Kiểm tra get_statistics tính toán chính xác số phiên active, thời lượng, lưu lượng."""
    service = AccountingService(sqlite_session)
    stats = service.get_statistics()

    assert stats["active_sessions"] == 1
    assert stats["total_duration"] == 3600 + 1800 + 600  # 6000s
    assert stats["total_download_bytes"] == 1048576 + 524288 + 256000
    assert stats["total_upload_bytes"] == 2097152 + 1048576 + 512000


def test_get_statistics_empty_database():
    """Kiểm tra get_statistics khi CSDL chưa có bất kỳ phiên nào."""
    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    db = TestingSession()

    try:
        service = AccountingService(db)
        stats = service.get_statistics()
        assert stats == {
            "active_sessions": 0,
            "total_duration": 0,
            "total_download_bytes": 0,
            "total_upload_bytes": 0,
        }
    finally:
        db.close()


def test_get_session_trend(sqlite_session: Session):
    """Kiểm tra get_session_trend trả về danh sách đúng số ngày và định dạng."""
    service = AccountingService(sqlite_session)
    trend = service.get_session_trend(days=7)

    assert len(trend) == 7
    for item in trend:
        assert "date" in item
        assert "sessions" in item
        assert isinstance(item["sessions"], int)


def test_list_auth_logs(sqlite_session: Session):
    """Kiểm tra list_auth_logs trả về nhật ký xác thực đúng phân trang và thứ tự."""
    service = AccountingService(sqlite_session)
    logs = service.list_auth_logs(skip=0, limit=10)

    assert len(logs) == 2
    assert logs[0]["username"] in ("user1", "user2")
    assert logs[0]["reply"] in ("Access-Accept", "Access-Reject")


def test_auth_logs_never_exposes_password(sqlite_session: Session):
    """BẢO MẬT: Kiểm tra list_auth_logs TUYỆT ĐỐI không bao giờ trả về trường pass."""
    service = AccountingService(sqlite_session)
    logs = service.list_auth_logs(skip=0, limit=50)

    for log in logs:
        assert "pass" not in log, "Trường 'pass' bị rò rỉ trong log!"
        assert "pass_" not in log, "Trường 'pass_' bị rò rỉ trong log!"
        assert "SuperSecretPassUser1" not in str(log), "Mật khẩu người dùng bị rò rỉ trong log!"
        assert "WrongPassAttempt" not in str(log), "Mật khẩu người dùng bị rò rỉ trong log!"


def test_get_dashboard_summary(sqlite_session: Session):
    """Kiểm tra get_dashboard_summary tổng hợp đúng số lượng users, nas, active, accepts, rejects."""
    service = AccountingService(sqlite_session)
    summary = service.get_dashboard_summary()

    assert summary["total_users"] == 2
    assert summary["total_nas"] == 1
    assert summary["active_sessions"] == 1
    assert summary["login_success_today"] == 1
    assert summary["login_failed_today"] == 1


def test_dashboard_summary_never_exposes_nas_secret(sqlite_session: Session):
    """BẢO MẬT: Kiểm tra get_dashboard_summary TUYỆT ĐỐI không để lộ nas.secret."""
    service = AccountingService(sqlite_session)
    summary = service.get_dashboard_summary()

    summary_str = str(summary)
    assert "RadiusSharedSecret999" not in summary_str
    assert "secret" not in summary
