"""
Bộ kiểm thử Service Layer cho Admin Password Change Service (Phase 0B - Step 3.4.7.1).
Kiểm tra tính đúng đắn của phương thức AdminAuthService.change_password():
- Xác minh mật khẩu hiện tại bằng PBKDF2 310k vòng băm.
- Ngăn chặn tái sử dụng mật khẩu cũ (PASSWORD_REUSED).
- Kiểm tra độ dài mật khẩu mới (8-128 ký tự), giữ nguyên khoảng trắng.
- Kiểm tra trạng thái tài khoản (inactive, không tồn tại).
- Bắt đầu transaction bằng transactional() TRƯỚC KHI thực hiện bất kỳ truy vấn CSDL nào.
- Quản lý transaction: Commit khi thành công, Rollback khi có exception.
- Cập nhật password_hash và updated_at an toàn, không rò rỉ dữ liệu nhạy cảm.

Kiểm thử độc lập trên SQLite in-memory, hoàn toàn không kết nối MariaDB thật.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Generator
from unittest.mock import MagicMock, patch

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.exceptions import (
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)
from app.core.security import hash_password, verify_password
from app.database import Base
from app.models.application import AppAdmin
from app.services.admin_auth import AdminAuthResult, AdminAuthService


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

    try:
        active_admin = AppAdmin(
            username="super_admin",
            password_hash=hash_password("CurrentSecretPass123!"),
            email="admin@enterprise.local",
            role="superadmin",
            is_active=True,
            created_at=datetime.now(timezone.utc) - timedelta(days=1),
            updated_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        disabled_admin = AppAdmin(
            username="disabled_admin",
            password_hash=hash_password("DisabledSecret123!"),
            email="disabled@enterprise.local",
            role="auditor",
            is_active=False,
            created_at=datetime.now(timezone.utc) - timedelta(days=1),
            updated_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        session.add(active_admin)
        session.add(disabled_admin)
        session.commit()

        session._active_admin = active_admin
        session._disabled_admin = disabled_admin

        yield session
    finally:
        session.close()


@pytest.fixture
def admin_service(sqlite_session: Session) -> AdminAuthService:
    """Khởi tạo AdminAuthService với Session được inject."""
    return AdminAuthService(db=sqlite_session)


@pytest.fixture
def active_admin(sqlite_session: Session) -> AppAdmin:
    """Lấy tài khoản active admin từ CSDL."""
    return sqlite_session._active_admin


@pytest.fixture
def disabled_admin(sqlite_session: Session) -> AppAdmin:
    """Lấy tài khoản disabled admin từ CSDL."""
    return sqlite_session._disabled_admin


# =============================================================================
# CÁC TEST CASES SERVICE UNIT TESTS CHO CHANGE_PASSWORD
# =============================================================================

def test_01_change_password_success(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
    sqlite_session: Session,
):
    """1. Đổi mật khẩu thành công: Trả về AdminAuthResult an toàn và cập nhật CSDL."""
    old_hash = active_admin.password_hash
    result = admin_service.change_password(
        admin_id=active_admin.id,
        current_password="CurrentSecretPass123!",
        new_password="NewSecurePass456!",
    )

    assert isinstance(result, AdminAuthResult)
    assert result.id == active_admin.id
    assert result.username == "super_admin"
    assert result.role == "superadmin"
    assert result.is_active is True

    # Kiểm tra bản ghi trong CSDL sau khi commit
    sqlite_session.refresh(active_admin)
    assert active_admin.password_hash != old_hash


def test_02_new_hash_verified_with_new_password(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
    sqlite_session: Session,
):
    """2. Chuỗi băm mới trong CSDL xác minh thành công bằng verify_password(new_password)."""
    admin_service.change_password(
        admin_id=active_admin.id,
        current_password="CurrentSecretPass123!",
        new_password="BrandNewPassword789!",
    )

    sqlite_session.refresh(active_admin)
    assert verify_password("BrandNewPassword789!", active_admin.password_hash) is True


def test_03_old_password_no_longer_verifies(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
    sqlite_session: Session,
):
    """3. Mật khẩu cũ không còn xác minh được với chuỗi băm mới."""
    admin_service.change_password(
        admin_id=active_admin.id,
        current_password="CurrentSecretPass123!",
        new_password="ReplacementPass123!",
    )

    sqlite_session.refresh(active_admin)
    assert verify_password("CurrentSecretPass123!", active_admin.password_hash) is False


def test_04_wrong_current_password_raises_unauthorized(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
    sqlite_session: Session,
):
    """4. Sai mật khẩu hiện tại → Ném UnauthorizedError với code INVALID_CREDENTIALS."""
    original_hash = active_admin.password_hash

    with pytest.raises(UnauthorizedError) as exc_info:
        admin_service.change_password(
            admin_id=active_admin.id,
            current_password="WrongCurrentPassword!",
            new_password="NewPassword123!",
        )

    assert exc_info.value.http_status == 401
    assert exc_info.value.code == "INVALID_CREDENTIALS"
    assert "không chính xác" in exc_info.value.message

    # Khẳng định hash trong CSDL không bị thay đổi
    sqlite_session.refresh(active_admin)
    assert active_admin.password_hash == original_hash


def test_05_admin_not_found_raises_not_found(admin_service: AdminAuthService):
    """5. Admin ID không tồn tại trong hệ thống → Ném NotFoundError (code: RESOURCE_NOT_FOUND)."""
    with pytest.raises(NotFoundError) as exc_info:
        admin_service.change_password(
            admin_id=99999,
            current_password="SomePassword123!",
            new_password="NewPassword123!",
        )

    assert exc_info.value.http_status == 404
    assert exc_info.value.code == "RESOURCE_NOT_FOUND"
    assert "không tồn tại" in exc_info.value.message


def test_06_inactive_admin_raises_forbidden(
    admin_service: AdminAuthService,
    disabled_admin: AppAdmin,
    sqlite_session: Session,
):
    """6. Admin inactive (is_active=False) → Ném ForbiddenError (code: ACCOUNT_INACTIVE)."""
    original_hash = disabled_admin.password_hash

    with pytest.raises(ForbiddenError) as exc_info:
        admin_service.change_password(
            admin_id=disabled_admin.id,
            current_password="DisabledSecret123!",
            new_password="NewValidPassword123!",
        )

    assert exc_info.value.http_status == 403
    assert exc_info.value.code == "ACCOUNT_INACTIVE"
    assert "vô hiệu hóa" in exc_info.value.message

    sqlite_session.refresh(disabled_admin)
    assert disabled_admin.password_hash == original_hash


def test_07_new_password_same_as_current_raises_validation_error(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
):
    """7. Mật khẩu mới trùng mật khẩu hiện tại → Ném ValidationError (code: PASSWORD_REUSED)."""
    with pytest.raises(ValidationError) as exc_info:
        admin_service.change_password(
            admin_id=active_admin.id,
            current_password="CurrentSecretPass123!",
            new_password="CurrentSecretPass123!",
        )

    assert exc_info.value.http_status == 422
    assert exc_info.value.code == "PASSWORD_REUSED"
    assert "trùng" in exc_info.value.message


def test_08_new_password_under_8_chars_raises_validation_error(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
):
    """8. Mật khẩu mới dưới 8 ký tự → Ném ValidationError (code: VALIDATION_ERROR)."""
    short_passwords = ["123", "short", "1234567"]
    for short_pwd in short_passwords:
        with pytest.raises(ValidationError) as exc_info:
            admin_service.change_password(
                admin_id=active_admin.id,
                current_password="CurrentSecretPass123!",
                new_password=short_pwd,
            )
        assert exc_info.value.http_status == 422
        assert exc_info.value.code == "VALIDATION_ERROR"
        assert "8 đến 128" in exc_info.value.message


def test_09_new_password_over_128_chars_raises_validation_error(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
):
    """9. Mật khẩu mới trên 128 ký tự → Ném ValidationError (code: VALIDATION_ERROR)."""
    overlong_pwd = "A" * 129
    with pytest.raises(ValidationError) as exc_info:
        admin_service.change_password(
            admin_id=active_admin.id,
            current_password="CurrentSecretPass123!",
            new_password=overlong_pwd,
        )

    assert exc_info.value.http_status == 422
    assert exc_info.value.code == "VALIDATION_ERROR"
    assert "8 đến 128" in exc_info.value.message


def test_10_password_whitespace_preserved(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
    sqlite_session: Session,
):
    """10. Mật khẩu có khoảng trắng hợp lệ ở đầu/cuối/giữa được giữ nguyên (không bị strip)."""
    pwd_with_spaces = "  Password With Spaces 123!  "
    admin_service.change_password(
        admin_id=active_admin.id,
        current_password="CurrentSecretPass123!",
        new_password=pwd_with_spaces,
    )

    sqlite_session.refresh(active_admin)
    # Xác minh đúng chính xác chuỗi có khoảng trắng
    assert verify_password(pwd_with_spaces, active_admin.password_hash) is True
    # Chuỗi đã strip không được khớp
    assert verify_password(pwd_with_spaces.strip(), active_admin.password_hash) is False


def test_11_updated_at_updated_on_success(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
    sqlite_session: Session,
):
    """11. updated_at được cập nhật mốc thời gian mới khi đổi mật khẩu thành công."""
    old_updated_at = active_admin.updated_at

    admin_service.change_password(
        admin_id=active_admin.id,
        current_password="CurrentSecretPass123!",
        new_password="NewValidPassword123!",
    )

    sqlite_session.refresh(active_admin)
    # Chuẩn hóa múi giờ để so sánh an toàn trên SQLite (SQLite lưu datetime dưới dạng naive UTC)
    new_dt = active_admin.updated_at.replace(tzinfo=timezone.utc) if active_admin.updated_at.tzinfo is None else active_admin.updated_at
    old_dt = old_updated_at.replace(tzinfo=timezone.utc) if old_updated_at.tzinfo is None else old_updated_at
    assert new_dt > old_dt


def test_12_exception_inside_transaction_rolls_back_changes(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
    sqlite_session: Session,
):
    """12. Exception xảy ra giữa transaction phải rollback toàn bộ thay đổi."""
    original_hash = active_admin.password_hash
    original_updated_at = active_admin.updated_at

    # Mô phỏng lỗi bất ngờ xảy ra khi băm hoặc ghi CSDL
    with patch("app.services.admin_auth.hash_password", side_effect=RuntimeError("Lỗi hệ thống bất ngờ")):
        with pytest.raises(RuntimeError) as exc_info:
            admin_service.change_password(
                admin_id=active_admin.id,
                current_password="CurrentSecretPass123!",
                new_password="NewValidPassword123!",
            )
        assert "Lỗi hệ thống bất ngờ" in str(exc_info.value)

    # Đảm bảo session không bị commit dữ liệu dở dang
    sqlite_session.refresh(active_admin)
    assert active_admin.password_hash == original_hash
    # Chuẩn hóa múi giờ so sánh
    current_dt = active_admin.updated_at.replace(tzinfo=timezone.utc) if active_admin.updated_at.tzinfo is None else active_admin.updated_at
    orig_dt = original_updated_at.replace(tzinfo=timezone.utc) if original_updated_at.tzinfo is None else original_updated_at
    assert current_dt == orig_dt


def test_13_transaction_committed_on_success(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
    sqlite_session: Session,
):
    """13. Khi thao tác thành công, transaction được commit và dữ liệu tồn tại bền vững."""
    admin_service.change_password(
        admin_id=active_admin.id,
        current_password="CurrentSecretPass123!",
        new_password="NewCommittedPassword123!",
    )

    # Đóng session hiện tại và mở session mới từ cùng database để kiểm tra tính bền vững (committed)
    session_factory = sessionmaker(bind=sqlite_session.bind)
    new_session = session_factory()
    try:
        fresh_admin = new_session.query(AppAdmin).filter(AppAdmin.id == active_admin.id).first()
        assert fresh_admin is not None
        assert verify_password("NewCommittedPassword123!", fresh_admin.password_hash) is True
    finally:
        new_session.close()


def test_14_no_manual_commit_or_rollback_outside_transactional(
    active_admin: AppAdmin,
    sqlite_session: Session,
):
    """14. Phương thức change_password không tự ý gọi session.commit() hoặc session.rollback() thủ công."""
    with patch.object(sqlite_session, "commit", wraps=sqlite_session.commit) as mock_commit, \
         patch.object(sqlite_session, "rollback", wraps=sqlite_session.rollback) as mock_rollback:
        service = AdminAuthService(db=sqlite_session)
        service.change_password(
            admin_id=active_admin.id,
            current_password="CurrentSecretPass123!",
            new_password="NewSecurePass789!",
        )

        # transactional context manager chịu trách nhiệm commit trên đối tượng trans,
        # không có lời gọi db.commit() hoặc db.rollback() nào nằm ngoài context manager
        assert mock_commit.call_count == 0
        assert mock_rollback.call_count == 0


def test_15_first_query_executed_after_transaction_starts(
    active_admin: AppAdmin,
    sqlite_session: Session,
):
    """
    15. Chứng minh truy vấn AppAdmin đầu tiên được thực hiện SAU KHI transaction bắt đầu:
    - Ghi nhận thứ tự gọi: transaction.begin() phải được gọi TRƯỚC query(AppAdmin).
    - Tại thời điểm query(AppAdmin) thực thi, db.in_transaction() phải là True từ transactional().
    """
    call_events = []
    original_query = sqlite_session.query

    def monitored_query(*args, **kwargs):
        # Kiểm tra xem session đã nằm trong transaction hay chưa ngay lúc query được gọi
        is_in_trans = sqlite_session.in_transaction()
        call_events.append(("query", is_in_trans))
        return original_query(*args, **kwargs)

    original_begin = sqlite_session.begin

    def monitored_begin(*args, **kwargs):
        call_events.append(("begin", sqlite_session.in_transaction()))
        return original_begin(*args, **kwargs)

    sqlite_session.query = monitored_query
    sqlite_session.begin = monitored_begin

    service = AdminAuthService(db=sqlite_session)
    try:
        service.change_password(
            admin_id=active_admin.id,
            current_password="CurrentSecretPass123!",
            new_password="VerifiedOrderPass123!",
        )
    finally:
        sqlite_session.query = original_query
        sqlite_session.begin = original_begin

    event_names = [e[0] for e in call_events]
    assert "begin" in event_names
    assert "query" in event_names
    # Khẳng định 'begin' xuất hiện trước 'query'
    assert event_names.index("begin") < event_names.index("query")
    # Khẳng định tại thời điểm query, session đã có transaction active từ begin()
    query_in_trans = [e[1] for e in call_events if e[0] == "query"]
    assert query_in_trans[0] is True


def test_16_invalid_admin_id_raises_validation_error(admin_service: AdminAuthService):
    """16. admin_id <= 0 hoặc không phải int → Ném ValidationError (code: VALIDATION_ERROR)."""
    invalid_ids = [-1, 0, "not_an_int", None]
    for bad_id in invalid_ids:
        with pytest.raises(ValidationError) as exc_info:
            admin_service.change_password(
                admin_id=bad_id,  # type: ignore
                current_password="CurrentSecretPass123!",
                new_password="NewValidPassword123!",
            )
        assert exc_info.value.http_status == 422
        assert exc_info.value.code == "VALIDATION_ERROR"


def test_17_result_dto_does_not_contain_password_or_hash(
    admin_service: AdminAuthService,
    active_admin: AppAdmin,
):
    """17. DTO kết quả AdminAuthResult tuyệt đối không chứa password hoặc password_hash."""
    result = admin_service.change_password(
        admin_id=active_admin.id,
        current_password="CurrentSecretPass123!",
        new_password="SafeResultPass123!",
    )

    res_dict = result.to_dict()
    assert "password" not in res_dict
    assert "password_hash" not in res_dict
    assert hasattr(result, "password") is False
    assert hasattr(result, "password_hash") is False
    assert "password" not in result
    assert "password_hash" not in result
