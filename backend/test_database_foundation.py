"""
Bộ kiểm thử đơn vị độc lập cho Database Engine, ORM Models và Schema Verifier (Phase 0B - Step 2).
Không yêu cầu máy chủ MariaDB đang chạy (sử dụng in-memory engine và metadata inspection).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Đảm bảo backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
)
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.dependencies import (
    DatabaseConnectionError,
    check_database_connection,
    handle_db_exception,
    sanitize_database_error,
    verify_schema_on_demand,
)
from app.database import Base, engine, get_db, SessionLocal
from app.models import (
    ALL_MODELS,
    AppAdmin,
    AppUser,
    Nas,
    NasReload,
    RadAcct,
    RadCheck,
    RadGroupCheck,
    RadGroupReply,
    RadPostAuth,
    RadReply,
    RadUserGroup,
    TableStatus,
    verify_schema,
)


# -----------------------------------------------------------------------------
# 1. KIỂM THỬ DATABASE ENGINE VÀ SESSION MANAGEMENT
# -----------------------------------------------------------------------------

def test_database_url_from_config():
    """Kiểm tra Engine sử dụng database_url từ config và cấu hình chuẩn PyMySQL."""
    assert str(engine.url).startswith("mysql+pymysql://")
    assert "radius_db" in str(engine.url)


def test_engine_lazy_does_not_connect_on_import():
    """Xác nhận Engine ở chế độ lazy, không tự mở kết nối mạng khi import."""
    # Kiểm tra pool chưa có kết nối checked out hoặc overflow nào
    assert engine.pool.checkedin() == 0
    assert engine.pool.checkedout() == 0


def test_sessionlocal_configured_properly():
    """Kiểm tra cấu hình SessionLocal factory."""
    assert SessionLocal.kw.get("autocommit") is False
    assert SessionLocal.kw.get("autoflush") is False
    assert SessionLocal.kw.get("bind") == engine


def test_get_db_yields_and_closes_session():
    """Kiểm tra dependency generator get_db() yield session và luôn đóng session sau khi dùng."""
    mock_session = MagicMock(spec=Session)

    with patch("app.database.SessionLocal", return_value=mock_session):
        db_generator = get_db()
        session = next(db_generator)

        # Đảm bảo generator yield đúng session instance
        assert session == mock_session
        assert mock_session.close.call_count == 0

        # Khi kết thúc generator (sau request), khối finally phải đóng session
        with pytest.raises(StopIteration):
            next(db_generator)

        assert mock_session.close.call_count == 1


# -----------------------------------------------------------------------------
# 2. KIỂM THỬ ĐỊNH NGHĨA 11 ORM MODELS
# -----------------------------------------------------------------------------

def test_all_11_models_declare_correct_table_names():
    """Kiểm tra 11 models khai báo đúng 100% tên bảng mục tiêu."""
    expected_tables = {
        "nas",
        "nasreload",
        "radacct",
        "radcheck",
        "radgroupcheck",
        "radgroupreply",
        "radpostauth",
        "radreply",
        "radusergroup",
        "app_admins",
        "app_users",
    }
    actual_tables = {model.__tablename__ for model in ALL_MODELS}
    assert actual_tables == expected_tables
    assert len(ALL_MODELS) == 11


def test_primary_keys_and_unique_constraints():
    """Kiểm tra khóa chính và ràng buộc unique trên các models."""
    # AppAdmin
    assert [c.name for c in AppAdmin.__table__.primary_key.columns] == ["id"]
    assert AppAdmin.__table__.columns["username"].unique is True

    # AppUser
    assert [c.name for c in AppUser.__table__.primary_key.columns] == ["id"]
    assert AppUser.__table__.columns["username"].unique is True

    # RadCheck
    assert [c.name for c in RadCheck.__table__.primary_key.columns] == ["id"]

    # Nas
    assert [c.name for c in Nas.__table__.primary_key.columns] == ["id"]

    # NasReload (IP là khóa chính)
    assert [c.name for c in NasReload.__table__.primary_key.columns] == ["nasipaddress"]

    # RadAcct
    assert [c.name for c in RadAcct.__table__.primary_key.columns] == ["radacctid"]
    assert RadAcct.__table__.columns["acctuniqueid"].unique is True


def test_app_user_does_not_contain_password_or_password_hash():
    """Kiểm tra tuyệt đối không có cột password hoặc password_hash trong app_users."""
    app_user_cols = {c.name for c in AppUser.__table__.columns}
    assert "password" not in app_user_cols
    assert "password_hash" not in app_user_cols
    assert "pass" not in app_user_cols
    assert hasattr(AppUser, "password") is False
    assert hasattr(AppUser, "password_hash") is False


def test_no_cascade_delete_on_historical_accounting():
    """Kiểm tra không có bất kỳ quan hệ cascade delete nào tới radacct và radpostauth."""
    # Không có foreign key vật lý từ radacct hoặc radpostauth trỏ về app_users
    assert len(RadAcct.__table__.foreign_keys) == 0
    assert len(RadPostAuth.__table__.foreign_keys) == 0

    # Không có relationship cascade trên AppUser
    assert len(AppUser.__mapper__.relationships) == 0


def test_app_admin_password_hash_column_spec():
    """Kiểm tra cột password_hash trên AppAdmin đủ độ dài lưu trữ hash PBKDF2."""
    pw_col = AppAdmin.__table__.columns["password_hash"]
    assert isinstance(pw_col.type, String)
    assert pw_col.type.length >= 255
    assert pw_col.nullable is False


# -----------------------------------------------------------------------------
# 3. KIỂM THỬ SCHEMA VERIFIER (READ-ONLY METADATA INSPECTION)
# -----------------------------------------------------------------------------

def test_schema_verifier_reports_missing_tables():
    """Kiểm tra Schema Verifier nhận diện chính xác các bảng chưa tồn tại (MISSING)."""
    test_engine = create_engine("sqlite:///:memory:")

    # Lúc đầu chưa có bảng nào trong test_engine
    summary = verify_schema(test_engine)

    assert summary.is_valid is False
    assert summary.overall_status == "MISSING_TABLES"
    assert len(summary.missing_tables) == 11
    assert "radcheck" in summary.missing_tables
    assert "app_admins" in summary.missing_tables
    assert "app_users" in summary.missing_tables
    assert summary.table_reports["radcheck"].status == TableStatus.MISSING


def test_schema_verifier_reports_ok_when_tables_match():
    """Kiểm tra Schema Verifier báo OK khi bảng tồn tại và khớp cấu trúc."""
    test_engine = create_engine("sqlite:///:memory:")

    # Tạo đầy đủ 11 bảng trên in-memory engine để mô phỏng CSDL chuẩn
    Base.metadata.create_all(bind=test_engine)

    summary = verify_schema(test_engine)

    assert summary.is_valid is True
    assert summary.overall_status == "OK"
    assert len(summary.missing_tables) == 0
    assert len(summary.mismatched_tables) == 0

    for table_name, report in summary.table_reports.items():
        assert report.status == TableStatus.OK
        assert len(report.missing_columns) == 0


def test_schema_verifier_reports_mismatch_on_missing_column():
    """Kiểm tra Schema Verifier phát hiện bảng bị thiếu cột (MISMATCH)."""
    test_engine = create_engine("sqlite:///:memory:")
    meta = MetaData()

    # Tạo bảng app_admins thiếu cột email và role
    Table(
        "app_admins",
        meta,
        Column("id", Integer, primary_key=True),
        Column("username", String(64), nullable=False),
        Column("password_hash", String(255), nullable=False),
        Column("is_active", Integer, nullable=False, default=1),
        Column("created_at", DateTime, nullable=False),
        Column("updated_at", DateTime, nullable=False),
    )
    meta.create_all(bind=test_engine)

    summary = verify_schema(test_engine)

    assert summary.is_valid is False
    assert "app_admins" in summary.mismatched_tables
    report = summary.table_reports["app_admins"]
    assert report.status == TableStatus.MISMATCH
    assert "email" in report.missing_columns
    assert "role" in report.missing_columns


def test_schema_verifier_does_not_execute_ddl():
    """Kiểm tra Schema Verifier tuyệt đối không thực hiện DDL (không tự tạo bảng)."""
    test_engine = create_engine("sqlite:///:memory:")

    # Chạy verifier trên CSDL rỗng
    summary = verify_schema(test_engine)
    assert len(summary.missing_tables) == 11

    # Kiểm tra sau khi chạy verifier, CSDL vẫn hoàn toàn rỗng (không bảng nào bị tạo ngầm)
    from sqlalchemy import inspect
    tables_after = inspect(test_engine).get_table_names()
    assert len(tables_after) == 0


def test_schema_verifier_reports_mismatch_on_column_length():
    """Kiểm tra Schema Verifier phát hiện sai lệch độ dài cột VARCHAR/String (MISMATCH)."""
    test_engine = create_engine("sqlite:///:memory:")
    meta = MetaData()

    # Bảng app_admins có username dài 32 ký tự thay vì 64 ký tự theo Model
    Table(
        "app_admins",
        meta,
        Column("id", Integer, primary_key=True),
        Column("username", String(32), unique=True, index=True, nullable=False),
        Column("password_hash", String(255), nullable=False),
        Column("email", String(255), nullable=True),
        Column("role", String(32), nullable=False, default="it_admin"),
        Column("is_active", Boolean, nullable=False, default=True),
        Column("created_at", DateTime, nullable=False),
        Column("updated_at", DateTime, nullable=False),
    )
    meta.create_all(bind=test_engine)

    summary = verify_schema(test_engine)

    assert summary.is_valid is False
    assert "app_admins" in summary.mismatched_tables
    report = summary.table_reports["app_admins"]
    assert report.status == TableStatus.MISMATCH
    assert "username" in report.mismatched_columns
    assert any("độ dài chuỗi" in d for d in report.details)


def test_schema_verifier_reports_mismatch_on_data_type():
    """Kiểm tra Schema Verifier phát hiện sai lệch kiểu dữ liệu cột (MISMATCH)."""
    test_engine = create_engine("sqlite:///:memory:")
    meta = MetaData()

    # Bảng app_admins có cột role kiểu Integer thay vì String(32)
    Table(
        "app_admins",
        meta,
        Column("id", Integer, primary_key=True),
        Column("username", String(64), unique=True, index=True, nullable=False),
        Column("password_hash", String(255), nullable=False),
        Column("email", String(255), nullable=True),
        Column("role", Integer, nullable=False, default=1),  # Kiểu sai: Integer thay vì String
        Column("is_active", Boolean, nullable=False, default=True),
        Column("created_at", DateTime, nullable=False),
        Column("updated_at", DateTime, nullable=False),
    )
    meta.create_all(bind=test_engine)

    summary = verify_schema(test_engine)

    assert summary.is_valid is False
    assert "app_admins" in summary.mismatched_tables
    report = summary.table_reports["app_admins"]
    assert report.status == TableStatus.MISMATCH
    assert "role" in report.mismatched_columns
    assert any("sai lệch kiểu dữ liệu" in d for d in report.details)


def test_schema_verifier_reports_mismatch_on_missing_unique_constraint():
    """Kiểm tra Schema Verifier phát hiện thiếu ràng buộc Unique bắt buộc (MISMATCH)."""
    test_engine = create_engine("sqlite:///:memory:")
    meta = MetaData()

    # Bảng app_admins có index trên username nhưng thiếu thuộc tính Unique
    Table(
        "app_admins",
        meta,
        Column("id", Integer, primary_key=True),
        Column("username", String(64), index=True, nullable=False),  # Có index nhưng KHÔNG unique!
        Column("password_hash", String(255), nullable=False),
        Column("email", String(255), nullable=True),
        Column("role", String(32), nullable=False, default="it_admin"),
        Column("is_active", Boolean, nullable=False, default=True),
        Column("created_at", DateTime, nullable=False),
        Column("updated_at", DateTime, nullable=False),
    )
    meta.create_all(bind=test_engine)

    summary = verify_schema(test_engine)

    assert summary.is_valid is False
    assert "app_admins" in summary.mismatched_tables
    report = summary.table_reports["app_admins"]
    assert report.status == TableStatus.MISMATCH
    assert "username" in report.mismatched_columns
    assert any("thiếu ràng buộc Unique" in d for d in report.details)


def test_schema_verifier_reports_mismatch_on_missing_index():
    """Kiểm tra Schema Verifier phát hiện thiếu Index bắt buộc (MISMATCH)."""
    test_engine = create_engine("sqlite:///:memory:")
    meta = MetaData()

    # Bảng nas đầy đủ cột nhưng cột nasname thiếu Index
    Table(
        "nas",
        meta,
        Column("id", Integer, primary_key=True),
        Column("nasname", String(128), nullable=False),  # Thiếu index!
        Column("shortname", String(32), nullable=True),
        Column("type", String(30), nullable=True),
        Column("ports", Integer, nullable=True),
        Column("secret", String(60), nullable=False),
        Column("server", String(64), nullable=True),
        Column("community", String(50), nullable=True),
        Column("description", String(200), nullable=True),
    )
    meta.create_all(bind=test_engine)

    summary = verify_schema(test_engine)

    assert summary.is_valid is False
    assert "nas" in summary.mismatched_tables
    report = summary.table_reports["nas"]
    assert report.status == TableStatus.MISMATCH
    assert "nasname" in report.mismatched_columns
    assert any("thiếu Index" in d for d in report.details)


def test_schema_verifier_integer_family_compatibility():
    """Kiểm tra tính tương thích giữa Integer và BigInteger không gây báo lỗi sai."""
    test_engine = create_engine("sqlite:///:memory:")
    meta = MetaData()

    # Bảng radcheck trong đó id sử dụng BigInteger thay vì Integer
    Table(
        "radcheck",
        meta,
        Column("id", BigInteger, primary_key=True),
        Column("username", String(64), nullable=False, default="", index=True),
        Column("attribute", String(64), nullable=False, default=""),
        Column("op", String(2), nullable=False, default=":="),
        Column("value", String(253), nullable=False, default=""),
    )
    meta.create_all(bind=test_engine)

    summary = verify_schema(test_engine)

    # Bảng radcheck không bị xem là MISMATCH do BigInteger tương thích với họ Integer
    assert "radcheck" not in summary.mismatched_tables
    report = summary.table_reports["radcheck"]
    assert report.status == TableStatus.OK
    assert len(report.mismatched_columns) == 0


# -----------------------------------------------------------------------------
# 4. KIỂM THỬ FASTAPI DATABASE DEPENDENCY VÀ ERROR HANDLING (Phase 0B - Step 3.1)
# -----------------------------------------------------------------------------

def test_get_db_dependency_yields_valid_session():
    """Kiểm tra dependency get_db() trả về SQLAlchemy Session hợp lệ và đang hoạt động."""
    db_gen = get_db()
    session = next(db_gen)
    assert isinstance(session, Session)
    assert session.is_active is True
    with pytest.raises(StopIteration):
        next(db_gen)


def test_session_closed_after_normal_usage():
    """Kiểm tra session được đóng an toàn sau khi sử dụng bình thường mà không rollback."""
    mock_session = MagicMock(spec=Session)

    with patch("app.database.SessionLocal", return_value=mock_session):
        db_gen = get_db()
        session = next(db_gen)
        assert session == mock_session
        assert mock_session.close.call_count == 0
        assert mock_session.rollback.call_count == 0

        with pytest.raises(StopIteration):
            next(db_gen)

        assert mock_session.close.call_count == 1
        assert mock_session.rollback.call_count == 0


def test_session_rolled_back_and_closed_on_exception():
    """Kiểm tra session tự động rollback và luôn đóng khi xảy ra exception trong request."""
    mock_session = MagicMock(spec=Session)

    with patch("app.database.SessionLocal", return_value=mock_session):
        db_gen = get_db()
        session = next(db_gen)
        assert session == mock_session
        assert mock_session.close.call_count == 0
        assert mock_session.rollback.call_count == 0

        # Giả lập request ném ra exception
        with pytest.raises(RuntimeError, match="Simulated HTTP request exception"):
            db_gen.throw(RuntimeError("Simulated HTTP request exception"))

        # Khối except phải rollback và khối finally phải đóng session
        assert mock_session.rollback.call_count == 1
        assert mock_session.close.call_count == 1


def test_engine_instance_reused_across_requests():
    """Kiểm tra không tạo engine mới cho từng request (tái sử dụng engine singleton)."""
    engines_seen = set()
    for _ in range(5):
        db_gen = get_db()
        session = next(db_gen)
        engines_seen.add(id(session.bind))
        try:
            next(db_gen)
        except StopIteration:
            pass

    assert len(engines_seen) == 1
    assert next(iter(engines_seen)) == id(engine)


def test_import_dependencies_does_not_require_active_db():
    """Kiểm tra việc import module dependencies không mở kết nối socket tới CSDL."""
    import importlib
    import app.core.dependencies as deps

    importlib.reload(deps)
    # Pool hoàn toàn chưa có kết nối đang checkout
    assert deps.engine.pool.checkedout() == 0
    assert deps.engine.pool.checkedin() == 0


def test_database_connection_failure_handled_safely():
    """Kiểm tra xử lý an toàn khi kết nối CSDL thất bại, không crash và không lặp vô hạn."""
    mock_bad_engine = MagicMock(spec=create_engine("sqlite:///:memory:").__class__)
    mock_bad_engine.connect.side_effect = OperationalError(
        statement="SELECT 1",
        params=None,
        orig=Exception("Can't connect to MySQL server on '127.0.0.1' (10061)"),
    )

    is_healthy, message = check_database_connection(mock_bad_engine)
    assert is_healthy is False
    assert "Database operational error" in message
    assert "10061" in message


def test_sanitize_database_error_masks_credentials():
    """Kiểm tra che giấu triệt để thông tin xác thực và mật khẩu trong chuỗi lỗi."""
    raw_error = "Failed to connect to mysql+pymysql://admin_user:SuperSecretPassword123@10.0.0.5:3306/radius_db"
    sanitized = sanitize_database_error(raw_error)

    assert "SuperSecretPassword123" not in sanitized
    assert "admin_user:***@" in sanitized

    # Kiểm tra hàm handle_db_exception cũng che giấu thông tin
    op_err = OperationalError(statement="SELECT 1", params=None, orig=Exception(raw_error))
    handled = handle_db_exception(op_err)
    assert "SuperSecretPassword123" not in handled
    assert "admin_user:***@" in handled


def test_verify_schema_on_demand_is_read_only():
    """Kiểm tra gọi Schema Verifier on-demand giữ nguyên chế độ read-only, không DDL."""
    test_engine = create_engine("sqlite:///:memory:")

    # Gọi verifier on-demand
    summary = verify_schema_on_demand(test_engine)
    assert summary.is_valid is False
    assert summary.overall_status == "MISSING_TABLES"

    # Kiểm tra CSDL vẫn hoàn toàn rỗng, không bị tự động sinh bảng
    from sqlalchemy import inspect
    tables = inspect(test_engine).get_table_names()
    assert len(tables) == 0


def test_check_database_connection_healthy_engine():
    """Kiểm tra hàm check_database_connection trả về True khi kết nối hoạt động bình thường."""
    sqlite_engine = create_engine("sqlite:///:memory:")
    is_healthy, message = check_database_connection(sqlite_engine)
    assert is_healthy is True
    assert "healthy" in message.lower()

