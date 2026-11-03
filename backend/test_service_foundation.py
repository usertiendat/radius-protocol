"""
Bộ kiểm thử đơn vị cho Service Layer Foundation và Business Exception Contract (Phase 0B - Step 3.3.2).
Kiểm thử hoàn toàn độc lập, sử dụng SQLite in-memory hoặc Mock, không kết nối MariaDB thật.
"""

import ast
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.exceptions import (
    BaseBusinessException,
    BusinessValidationError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceUnavailableError,
    UnauthorizedError,
    ValidationError,
)
from app.services import BaseService
from app.services.transaction import TransactionAlreadyActiveError, transactional


# -----------------------------------------------------------------------------
# 1. KIỂM THỬ BUSINESS EXCEPTION CONTRACT
# -----------------------------------------------------------------------------

def test_business_exceptions_have_correct_code():
    """Kiểm tra toàn bộ Business Exceptions có đúng error code mặc định và hỗ trợ ghi đè."""
    # 1. Mã lỗi mặc định
    assert NotFoundError().code == "RESOURCE_NOT_FOUND"
    assert ConflictError().code == "RESOURCE_CONFLICT"
    assert UnauthorizedError().code == "UNAUTHORIZED"
    assert ForbiddenError().code == "FORBIDDEN"
    assert ServiceUnavailableError().code == "SERVICE_UNAVAILABLE"
    assert ValidationError().code == "VALIDATION_ERROR"
    assert BusinessValidationError().code == "VALIDATION_ERROR"

    # 2. Hỗ trợ ghi đè mã lỗi tùy biến
    custom_err = NotFoundError(message="Người dùng không tồn tại", code="USER_NOT_FOUND")
    assert custom_err.code == "USER_NOT_FOUND"
    assert custom_err.message == "Người dùng không tồn tại"
    assert str(custom_err) == "[USER_NOT_FOUND] Người dùng không tồn tại"


def test_business_exceptions_have_correct_http_status_metadata():
    """Kiểm tra Business Exceptions chứa đúng HTTP status metadata cho Router ánh xạ."""
    assert NotFoundError.http_status == 404
    assert ConflictError.http_status == 409
    assert UnauthorizedError.http_status == 401
    assert ForbiddenError.http_status == 403
    assert ServiceUnavailableError.http_status == 503
    assert ValidationError.http_status == 422
    assert BusinessValidationError.http_status == 422

    # Giá trị metadata là integer chuẩn
    for exc_cls in [
        NotFoundError,
        ConflictError,
        UnauthorizedError,
        ForbiddenError,
        ServiceUnavailableError,
        ValidationError,
    ]:
        assert isinstance(exc_cls.http_status, int)


def test_business_exceptions_independent_of_fastapi():
    """Xác nhận hệ thống Business Exceptions độc lập hoàn toàn với FastAPI / Starlette."""
    # Không kế thừa từ bất kỳ class nào của FastAPI hay Starlette
    assert issubclass(BaseBusinessException, Exception)

    # Đọc AST module để xác nhận không import fastapi hay HTTPException
    exceptions_file = BACKEND_DIR / "app" / "core" / "exceptions.py"
    tree = ast.parse(exceptions_file.read_text(encoding="utf-8"))

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

    assert "fastapi" not in imported_names
    assert "starlette" not in imported_names
    assert "HTTPException" not in imported_names


# -----------------------------------------------------------------------------
# 2. KIỂM THỬ TRANSACTION MANAGEMENT (transactional)
# -----------------------------------------------------------------------------

def test_transactional_commits_on_success():
    """Kiểm tra transactional context manager tự động commit khi khối lệnh thành công."""
    mock_session = MagicMock(spec=Session)
    mock_session.in_transaction.return_value = False
    mock_trans = MagicMock()
    mock_session.begin.return_value = mock_trans

    with transactional(mock_session) as db:
        assert db == mock_session

    mock_session.in_transaction.assert_called_once()
    mock_session.begin.assert_called_once()
    mock_trans.commit.assert_called_once()
    mock_trans.rollback.assert_not_called()


def test_transactional_rollbacks_on_exception():
    """Kiểm tra transactional context manager tự động rollback khi phát sinh exception."""
    mock_session = MagicMock(spec=Session)
    mock_session.in_transaction.return_value = False
    mock_trans = MagicMock()
    mock_session.begin.return_value = mock_trans

    with pytest.raises(ConflictError, match="Dữ liệu bị trùng"):
        with transactional(mock_session):
            raise ConflictError("Dữ liệu bị trùng")

    mock_session.in_transaction.assert_called_once()
    mock_session.begin.assert_called_once()
    mock_trans.commit.assert_not_called()
    mock_trans.rollback.assert_called_once()


def test_transactional_preserves_original_exception_when_rollback_fails():
    """Kiểm tra ngoại lệ nghiệp vụ gốc không bị che khuất nếu quá trình rollback gặp sự cố."""
    mock_session = MagicMock(spec=Session)
    mock_session.in_transaction.return_value = False
    mock_trans = MagicMock()
    mock_trans.rollback.side_effect = RuntimeError("Mất kết nối mạng khi đang rollback")
    mock_session.begin.return_value = mock_trans

    with pytest.raises(ConflictError) as exc_info:
        with transactional(mock_session):
            raise ConflictError("Lỗi nghiệp vụ gốc")

    # Ngoại lệ ném ra phải là ConflictError ban đầu, không bị RuntimeError thay thế
    assert isinstance(exc_info.value, ConflictError)
    assert exc_info.value.code == "RESOURCE_CONFLICT"
    assert "Lỗi nghiệp vụ gốc" in exc_info.value.message


def test_transactional_rejects_already_active_transaction_mock():
    """Kiểm tra transactional từ chối Session đã có transaction đang chạy (mock)."""
    mock_session = MagicMock(spec=Session)
    mock_session.in_transaction.return_value = True

    with pytest.raises(TransactionAlreadyActiveError) as exc_info:
        with transactional(mock_session):
            pytest.fail("Khối code bên trong không được phép thực thi")

    assert "Session đã có transaction đang hoạt động" in str(exc_info.value)
    mock_session.begin.assert_not_called()
    mock_session.commit.assert_not_called()
    mock_session.rollback.assert_not_called()


def test_transactional_with_real_sqlite_session():
    """Kiểm tra hoạt động thực tế của transactional với in-memory SQLite (commit & rollback)."""
    engine = create_engine("sqlite:///:memory:")
    meta = MetaData()
    test_table = Table(
        "test_items",
        meta,
        Column("id", Integer, primary_key=True),
        Column("name", String(50), nullable=False),
    )
    meta.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    # 1. Kiểm tra Commit thành công khi session sạch
    session1 = TestingSession()
    try:
        assert session1.in_transaction() is False
        with transactional(session1):
            assert session1.in_transaction() is True
            session1.execute(test_table.insert().values(id=1, name="Item One"))

        # Sau khi ra khỏi transactional, transaction đã được commit
        result = session1.execute(test_table.select()).fetchall()
        assert len(result) == 1
        assert result[0][1] == "Item One"
    finally:
        session1.close()

    # 2. Kiểm tra Rollback khi lỗi
    session2 = TestingSession()
    try:
        with pytest.raises(ValueError):
            with transactional(session2):
                session2.execute(test_table.insert().values(id=2, name="Item Two"))
                raise ValueError("Giả lập lỗi giữa chừng")

        # Xác nhận Item Two không tồn tại trong DB do đã rollback
        result = session2.execute(test_table.select().where(test_table.c.id == 2)).fetchall()
        assert len(result) == 0
    finally:
        session2.close()


def test_transactional_rejects_already_active_transaction_real_session():
    """Kiểm tra transactional từ chối khi real session đã có transaction (autobegin hoặc explicit begin)."""
    from sqlalchemy.pool import StaticPool
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    meta = MetaData()
    test_table = Table(
        "active_tx_items",
        meta,
        Column("id", Integer, primary_key=True),
        Column("name", String(50), nullable=False),
    )
    meta.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSession()

    try:
        # Tầng ngoài bắt đầu một transaction (Top-level transaction)
        session.begin()
        assert session.in_transaction() is True

        # Khi Service con cố ý gọi transactional(session) -> bị từ chối
        with pytest.raises(TransactionAlreadyActiveError) as exc_info:
            with transactional(session):
                pytest.fail("Code bên trong không được chạy")

        assert "Session đã có transaction đang hoạt động" in str(exc_info.value)
    finally:
        session.rollback()
        session.close()


def test_rejected_transactional_does_not_commit_outer_pending_data():
    """
    Kiểm tra cơ chế an toàn: Khi transactional(db) từ chối session đang active,
    nó KHÔNG commit dữ liệu pending của tầng ngoài, bảo toàn quyền rollback của caller.
    """
    from sqlalchemy.pool import StaticPool
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    meta = MetaData()
    test_table = Table(
        "outer_tx_items",
        meta,
        Column("id", Integer, primary_key=True),
        Column("name", String(50), nullable=False),
    )
    meta.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    session = TestingSession()
    try:
        # 1. Tầng ngoài mở transaction và insert bản ghi dở dang (chưa commit)
        session.begin()
        session.execute(test_table.insert().values(id=100, name="Pending Outer Data"))
        assert session.in_transaction() is True

        # 2. Service con gọi transactional(session) -> bị ném TransactionAlreadyActiveError
        with pytest.raises(TransactionAlreadyActiveError):
            with transactional(session):
                pass

        # 3. Tầng ngoài quyết định rollback toàn bộ vì Service con vi phạm hợp đồng
        session.rollback()

        # 4. Kiểm tra session mới: "Pending Outer Data" hoàn toàn không có trong DB
        verify_session = TestingSession()
        try:
            records = verify_session.execute(test_table.select()).fetchall()
            assert len(records) == 0, "Dữ liệu pending bên ngoài không được phép commit!"
        finally:
            verify_session.close()
    finally:
        session.close()


def test_transactional_requires_valid_session():
    """Kiểm tra transactional từ chối tham số không phải là SQLAlchemy Session."""
    with pytest.raises(TypeError, match="Tham số 'db' phải là một instance hợp lệ"):
        with transactional(None):  # type: ignore
            pass

    with pytest.raises(TypeError, match="Tham số 'db' phải là một instance hợp lệ"):
        with transactional("invalid_session_type"):  # type: ignore
            pass


def test_transactional_does_not_create_nested_transaction():
    """Kiểm tra transactional hoạt động trực tiếp trên session, không tự tạo nested savepoint."""
    engine = create_engine("sqlite:///:memory:")
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSession()

    try:
        with transactional(session):
            # Không ở trong nested transaction (SAVEPOINT)
            assert session.in_nested_transaction() is False
    finally:
        session.close()


# -----------------------------------------------------------------------------
# 3. KIỂM THỬ SERVICE LAYER FOUNDATION (BaseService)
# -----------------------------------------------------------------------------

def test_base_service_requires_external_session():
    """Kiểm tra BaseService bắt buộc nhận Session từ bên ngoài qua Dependency Injection."""
    mock_session = MagicMock(spec=Session)
    service = BaseService(db=mock_session)
    assert service.db == mock_session

    # Từ chối khởi tạo nếu không truyền Session hợp lệ
    with pytest.raises(TypeError, match="Tham số 'db' phải là một instance hợp lệ"):
        BaseService(db="invalid_session")  # type: ignore

    with pytest.raises(TypeError, match="Tham số 'db' phải là một instance hợp lệ"):
        BaseService(db=None)  # type: ignore


def test_service_does_not_create_new_engine_or_session():
    """Kiểm tra Service không tự khởi tạo Engine hay SessionLocal."""
    base_service_file = BACKEND_DIR / "app" / "services" / "base.py"
    tree = ast.parse(base_service_file.read_text(encoding="utf-8"))

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


def test_service_uses_injected_session_correctly():
    """Kiểm tra Service con kế thừa BaseService và sử dụng đúng session được tiêm."""
    engine = create_engine("sqlite:///:memory:")
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = TestingSession()

    class SampleDummyService(BaseService):
        def ping_db(self) -> int:
            return self.db.execute(text("SELECT 100")).scalar()

    try:
        dummy_service = SampleDummyService(db=session)
        assert dummy_service.db is session
        val = dummy_service.ping_db()
        assert val == 100
    finally:
        session.close()
