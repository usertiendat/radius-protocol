"""
Transaction Management Utility cho Service Layer.
Chuẩn hóa ranh giới giao dịch (Transaction Boundary) theo mô hình:
Explicit Top-level Transaction Ownership:
- Chỉ Top-level Service được phép khởi tạo và quản lý transaction (commit/rollback).
- Từ chối thực hiện nếu Session đã có transaction đang hoạt động để ngăn chặn commit sớm transaction ngoài.
- Không tự động tạo SAVEPOINT hay begin_nested().
- Commit khi thành công, Rollback khi có exception.
- Sử dụng bare `raise` để bảo toàn tuyệt đối ngoại lệ và traceback gốc (ngoại lệ rollback không che khuất ngoại lệ gốc).
"""

from contextlib import contextmanager
import logging
from typing import Generator
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class TransactionAlreadyActiveError(Exception):
    """
    Ngoại lệ an toàn ném ra khi cố gắng mở một transaction mới trên một Session
    đã có transaction đang hoạt động.
    Ngăn ngừa triệt để nguy cơ Service con commit sớm transaction của Service cha/tầng ngoài.
    """

    def __init__(
        self,
        message: str = (
            "Session đã có transaction đang hoạt động. "
            "Chỉ Top-level Service được phép quản lý transaction; "
            "Service con không được tự ý commit/rollback."
        ),
    ) -> None:
        super().__init__(message)
        self.message = message


@contextmanager
def transactional(db: Session) -> Generator[Session, None, None]:
    """
    Context manager chuẩn hóa việc quản lý Transaction tại tầng Service.

    Quy tắc an toàn (Explicit Top-level Transaction Ownership):
    1. Kiểm tra session hợp lệ (isinstance sqlalchemy.orm.Session).
    2. Kiểm tra xem session đã có transaction đang hoạt động hay chưa (db.in_transaction()).
       Nếu đã có transaction -> ném TransactionAlreadyActiveError, KHÔNG commit/rollback transaction ngoài.
    3. Nếu chưa có transaction -> khởi tạo transaction tường minh (trans = db.begin()).
    4. Commit khi khối lệnh hoàn thành thành công (trans.commit()).
    5. Rollback khi phát sinh exception (trans.rollback()).
    6. Nếu quá trình rollback gặp sự cố, log cảnh báo và dùng bare raise để bảo toàn tuyệt đối
       ngoại lệ gốc cùng traceback ban đầu.
    """
    if not isinstance(db, Session):
        raise TypeError("Tham số 'db' phải là một instance hợp lệ của sqlalchemy.orm.Session")

    # Từ chối nếu Session đã có transaction đang active từ tầng ngoài
    if db.in_transaction():
        raise TransactionAlreadyActiveError(
            "Session đã có transaction đang hoạt động. "
            "Chỉ Top-level Service được phép quản lý transaction; "
            "Service con không được tự ý commit/rollback."
        )

    # Khởi tạo transaction tường minh thuộc quyền sở hữu của context manager này
    trans = db.begin()
    try:
        yield db
        trans.commit()
    except Exception:
        try:
            trans.rollback()
        except Exception as rb_exc:
            logger.error(
                "Lỗi phát sinh trong quá trình rollback transaction: %s",
                rb_exc,
            )
        raise
