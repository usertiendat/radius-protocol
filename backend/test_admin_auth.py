"""
Bộ kiểm thử đơn vị cho Admin Authentication Service (Phase 0B - Step 3.4.1).
Kiểm thử độc lập với SQLite in-memory, không kết nối MariaDB thật.
"""

import ast
from datetime import datetime, timezone
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.exceptions import ForbiddenError, UnauthorizedError, ValidationError
from app.core.security import hash_password
from app.database import Base
from app.models.application import AppAdmin
from app.models.radius import RadCheck
from app.services import AdminAuthResult, AdminAuthService


@pytest.fixture
def sqlite_db_session():
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
        # Seed dữ liệu quản trị viên mẫu
        active_admin = AppAdmin(
            username="it_admin",
            password_hash=hash_password("SuperSecretPass123!"),
            email="admin@enterprise.local",
            role="it_admin",
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        inactive_admin = AppAdmin(
            username="disabled_admin",
            password_hash=hash_password("DisabledPass123!"),
            email="disabled@enterprise.local",
            role="auditor",
            is_active=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(active_admin)
        session.add(inactive_admin)
        session.commit()

        yield session
    finally:
        session.close()


# -----------------------------------------------------------------------------
# 1. KIỂM THỬ XÁC THỰC THÀNH CÔNG VÀ THẤT BẠI
# -----------------------------------------------------------------------------

def test_admin_login_success(sqlite_db_session):
    """1. Kiểm tra Admin hợp lệ và active đăng nhập thành công, trả về đúng DTO."""
    service = AdminAuthService(db=sqlite_db_session)
    result = service.authenticate("it_admin", "SuperSecretPass123!")

    assert isinstance(result, AdminAuthResult)
    assert result.username == "it_admin"
    assert result.email == "admin@enterprise.local"
    assert result.role == "it_admin"
    assert result.is_active is True
    assert isinstance(result.id, int)


def test_admin_login_username_not_found(sqlite_db_session):
    """2. Kiểm tra từ chối khi username không tồn tại."""
    service = AdminAuthService(db=sqlite_db_session)

    with pytest.raises(UnauthorizedError) as exc_info:
        service.authenticate("non_existent_admin", "AnyPassword123!")

    assert exc_info.value.code == "INVALID_CREDENTIALS"
    assert exc_info.value.message == "Tên đăng nhập hoặc mật khẩu không chính xác."
    assert exc_info.value.http_status == 401


def test_admin_login_wrong_password(sqlite_db_session):
    """3. Kiểm tra từ chối khi password không chính xác."""
    service = AdminAuthService(db=sqlite_db_session)

    with pytest.raises(UnauthorizedError) as exc_info:
        service.authenticate("it_admin", "WrongPassword999!")

    assert exc_info.value.code == "INVALID_CREDENTIALS"
    assert exc_info.value.message == "Tên đăng nhập hoặc mật khẩu không chính xác."
    assert exc_info.value.http_status == 401


def test_admin_login_disabled_account(sqlite_db_session):
    """4. Kiểm tra từ chối khi tài khoản Admin bị vô hiệu hóa (is_active=False)."""
    service = AdminAuthService(db=sqlite_db_session)

    with pytest.raises(ForbiddenError) as exc_info:
        service.authenticate("disabled_admin", "DisabledPass123!")

    assert exc_info.value.code == "ACCOUNT_INACTIVE"
    assert "vô hiệu hóa" in exc_info.value.message
    assert exc_info.value.http_status == 403


# -----------------------------------------------------------------------------
# 2. KIỂM THỬ VALIDATION THAM SỐ ĐẦU VÀO
# -----------------------------------------------------------------------------

def test_admin_login_invalid_username(sqlite_db_session):
    """5. Kiểm tra validation khi username rỗng, None hoặc không hợp lệ."""
    service = AdminAuthService(db=sqlite_db_session)

    invalid_usernames = ["", "   ", None, 12345, []]
    for bad_user in invalid_usernames:
        with pytest.raises(ValidationError) as exc_info:
            service.authenticate(bad_user, "ValidPass123!")  # type: ignore

        assert exc_info.value.code == "VALIDATION_ERROR"
        assert exc_info.value.http_status == 422


def test_admin_login_invalid_password(sqlite_db_session):
    """6. Kiểm tra validation khi password rỗng, None hoặc không hợp lệ."""
    service = AdminAuthService(db=sqlite_db_session)

    invalid_passwords = ["", None, 12345, {}]
    for bad_pwd in invalid_passwords:
        with pytest.raises(ValidationError) as exc_info:
            service.authenticate("it_admin", bad_pwd)  # type: ignore

        assert exc_info.value.code == "VALIDATION_ERROR"
        assert exc_info.value.http_status == 422


# -----------------------------------------------------------------------------
# 3. KIỂM THỬ BẢO VỆ DỮ LIỆU NHẠY CẢM TRONG KẾT QUẢ
# -----------------------------------------------------------------------------

def test_admin_result_does_not_contain_password(sqlite_db_session):
    """7. Kiểm tra tuyệt đối không có trường password trong kết quả trả về."""
    service = AdminAuthService(db=sqlite_db_session)
    result = service.authenticate("it_admin", "SuperSecretPass123!")

    # 1. Thuộc tính không tồn tại
    assert hasattr(result, "password") is False

    # 2. Không có trong dictionary
    res_dict = result.to_dict()
    assert "password" not in res_dict

    # 3. Không có trong toán tử in
    assert ("password" in result) is False

    # 4. Truy cập qua [] bị chặn
    with pytest.raises(KeyError):
        _ = result["password"]


def test_admin_result_does_not_contain_password_hash(sqlite_db_session):
    """8. Kiểm tra tuyệt đối không có trường password_hash trong kết quả trả về."""
    service = AdminAuthService(db=sqlite_db_session)
    result = service.authenticate("it_admin", "SuperSecretPass123!")

    # 1. Thuộc tính không tồn tại
    assert hasattr(result, "password_hash") is False

    # 2. Không có trong dictionary
    res_dict = result.to_dict()
    assert "password_hash" not in res_dict

    # 3. Không có trong toán tử in
    assert ("password_hash" in result) is False

    # 4. Truy cập qua [] bị chặn
    with pytest.raises(KeyError):
        _ = result["password_hash"]


# -----------------------------------------------------------------------------
# 4. KIỂM THỬ QUẢN LÝ SESSION VÀ TRANSACTION CONTRACT
# -----------------------------------------------------------------------------

def test_service_uses_injected_session(sqlite_db_session):
    """9. Kiểm tra Service bắt buộc sử dụng Session được inject từ ngoài."""
    service = AdminAuthService(db=sqlite_db_session)
    assert service.db is sqlite_db_session

    # Từ chối nếu không truyền Session hợp lệ
    with pytest.raises(TypeError, match="Tham số 'db' phải là một instance hợp lệ"):
        AdminAuthService(db="invalid_session")  # type: ignore


def test_service_does_not_create_new_engine_or_session():
    """10. Kiểm tra Service không tự import hoặc khởi tạo Engine/SessionLocal."""
    auth_service_file = BACKEND_DIR / "app" / "services" / "admin_auth.py"
    tree = ast.parse(auth_service_file.read_text(encoding="utf-8"))

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

    assert "create_engine" not in imported_names
    assert "SessionLocal" not in imported_names
    assert "engine" not in imported_names


def test_service_does_not_commit():
    """11. Kiểm tra AdminAuthService là thao tác chỉ đọc, tuyệt đối không tự gọi commit."""
    mock_session = MagicMock(spec=Session)
    mock_admin = MagicMock(spec=AppAdmin)
    mock_admin.username = "mock_admin"
    mock_admin.password_hash = hash_password("MockPass123!")
    mock_admin.is_active = True
    mock_session.query.return_value.filter.return_value.first.return_value = mock_admin

    service = AdminAuthService(db=mock_session)
    _ = service.authenticate("mock_admin", "MockPass123!")

    # Tuyệt đối không commit
    mock_session.commit.assert_not_called()


def test_service_does_not_rollback():
    """12. Kiểm tra AdminAuthService không tự ý gọi rollback trong luồng đọc."""
    mock_session = MagicMock(spec=Session)
    mock_session.query.return_value.filter.return_value.first.return_value = None

    service = AdminAuthService(db=mock_session)
    with pytest.raises(UnauthorizedError):
        service.authenticate("unknown_user", "AnyPass123!")

    # Tuyệt đối không rollback
    mock_session.rollback.assert_not_called()


# -----------------------------------------------------------------------------
# 5. KIỂM THỬ BẢO MẬT & PHÂN BIỆT VỚI FREERADIUS NETWORK USERS
# -----------------------------------------------------------------------------

def test_username_not_found_and_wrong_password_have_same_error_type_and_code(sqlite_db_session):
    """13. Kiểm tra trường hợp sai username và sai password trả về cùng loại lỗi, cùng mã lỗi và message."""
    service = AdminAuthService(db=sqlite_db_session)

    # Trường hợp A: Username không tồn tại
    with pytest.raises(UnauthorizedError) as exc_user_missing:
        service.authenticate("ghost_admin", "Pass123!")

    # Trường hợp B: Password sai
    with pytest.raises(UnauthorizedError) as exc_wrong_pwd:
        service.authenticate("it_admin", "WrongPass123!")

    # Xác minh tính đồng nhất tuyệt đối để chống username enumeration
    assert exc_user_missing.type is exc_wrong_pwd.type
    assert exc_user_missing.value.code == exc_wrong_pwd.value.code == "INVALID_CREDENTIALS"
    assert exc_user_missing.value.message == exc_wrong_pwd.value.message == "Tên đăng nhập hoặc mật khẩu không chính xác."
    assert exc_user_missing.value.http_status == exc_wrong_pwd.value.http_status == 401


def test_admin_auth_does_not_use_radcheck(sqlite_db_session):
    """
    14. Kiểm tra xác thực Dashboard Admin hoàn toàn tách biệt, không sử dụng bảng radcheck của FreeRADIUS:
    - Nếu tài khoản chỉ có trong radcheck mà không có trong app_admins, xác thực phải thất bại.
    - Source code của admin_auth.py không import hoặc tham chiếu tới RadCheck.
    """
    # 1. AST check: Source code không import RadCheck hay radcheck
    auth_service_file = BACKEND_DIR / "app" / "services" / "admin_auth.py"
    tree = ast.parse(auth_service_file.read_text(encoding="utf-8"))
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

    # 2. Thêm tài khoản mạng vào bảng radcheck
    rad_user = RadCheck(
        username="network_user_only",
        attribute="Cleartext-Password",
        op=":=",
        value="NetworkPass123!",
    )
    sqlite_db_session.add(rad_user)
    sqlite_db_session.commit()

    # 3. Xác thực Dashboard Admin với network_user_only phải thất bại (vì AdminAuthService không đọc radcheck)
    service = AdminAuthService(db=sqlite_db_session)
    with pytest.raises(UnauthorizedError) as exc_info:
        service.authenticate("network_user_only", "NetworkPass123!")

    assert exc_info.value.code == "INVALID_CREDENTIALS"


def test_timing_attack_mitigation_runs_dummy_hash(sqlite_db_session):
    """Kiểm tra cơ chế phòng vệ Timing Attack: gọi verify_password giả lập khi username không tồn tại."""
    from app.core.security import verify_password as real_verify_password
    service = AdminAuthService(db=sqlite_db_session)

    with patch("app.services.admin_auth.verify_password", wraps=real_verify_password) as mock_verify:
        with pytest.raises(UnauthorizedError):
            service.authenticate("nonexistent_user", "AnyPassword123!")

        # Hàm verify_password phải được gọi ít nhất 1 lần với DUMMY_PASSWORD_HASH
        mock_verify.assert_called_once()
        args, _ = mock_verify.call_args
        assert args[0] == "AnyPassword123!"
        assert "pbkdf2_sha256$310000$" in args[1]
