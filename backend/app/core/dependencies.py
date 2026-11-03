"""
Core Dependencies cho FastAPI Backend.
Cung cấp các dependency nền tảng dùng chung:
- Database Session Lifecycle Management (`get_db`).
- Database Connectivity & Health Check (`check_database_connection`).
- Error Sanitization & Safe Exception Handling (`sanitize_database_error`, `handle_db_exception`).
- On-Demand Schema Verification (`verify_schema_on_demand`).

Lưu ý kiến trúc:
- Tuyệt đối không mở kết nối database khi import module.
- Không chứa logic nghiệp vụ, Admin Auth, hay JWT Authorization (được tách ở các bước sau).
- Không tự động retry vô hạn và không thực hiện DDL khi kết nối thất bại.
"""

import re
from typing import Generator, Optional, Tuple
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database import SessionLocal, engine, get_db
from app.models.verifier import SchemaVerificationSummary, verify_schema


class DatabaseConnectionError(Exception):
    """Ngoại lệ an toàn đại diện cho lỗi kết nối CSDL mà không làm lộ secret."""

    def __init__(self, message: str = "Database connection failed or unavailable."):
        super().__init__(message)
        self.message = message


def sanitize_database_error(error: Exception | str) -> str:
    """
    Loại bỏ thông tin nhạy cảm (mật khẩu, credentials trong URL) khỏi thông báo lỗi
    trước khi trả về cho client hoặc ghi log.
    """
    msg = str(error)
    # 1. Che giấu mật khẩu trong URL dạng ://user:password@ -> ://user:***@
    msg = re.sub(r"://([^:/@\s]+):([^@\s]+)@", r"://\1:***@", msg)
    # 2. Che giấu mật khẩu trực tiếp nếu DB_PASSWORD được cấu hình
    if settings.DB_PASSWORD and settings.DB_PASSWORD in msg:
        msg = msg.replace(settings.DB_PASSWORD, "***")
    return msg


def handle_db_exception(exc: Exception) -> str:
    """
    Xử lý và chuẩn hóa các ngoại lệ database:
    - Bóc tách thông tin nhạy cảm.
    - Phân loại lỗi OperationalError, SQLAlchemyError, etc.
    - Trả về thông điệp an toàn cho log hoặc HTTP response.
    """
    sanitized = sanitize_database_error(exc)
    if isinstance(exc, OperationalError):
        return f"Database operational error: {sanitized}"
    elif isinstance(exc, SQLAlchemyError):
        return f"Database error: {sanitized}"
    return f"Unexpected database error: {sanitized}"


def check_database_connection(
    target_engine: Optional[Engine] = None,
) -> Tuple[bool, str]:
    """
    Kiểm tra nhanh kết nối CSDL (Health ping).
    - Sử dụng target_engine hoặc default engine.
    - Không retry vô hạn.
    - Không phát sinh DDL hay tạo bảng.
    - Che giấu toàn bộ thông tin nhạy cảm nếu xảy ra lỗi.
    - Trả về tuple: (is_healthy: bool, message: str)
    """
    eng = target_engine or engine
    try:
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "Database connection is healthy."
    except OperationalError as exc:
        safe_msg = handle_db_exception(exc)
        return False, safe_msg
    except SQLAlchemyError as exc:
        safe_msg = handle_db_exception(exc)
        return False, safe_msg
    except Exception as exc:
        safe_msg = sanitize_database_error(exc)
        return False, f"Unexpected error while connecting to database: {safe_msg}"


def verify_schema_on_demand(
    target_engine: Optional[Engine] = None,
) -> SchemaVerificationSummary:
    """
    Chạy Schema Verifier theo yêu cầu rõ ràng (On-Demand).
    - Hoàn toàn chỉ đọc (Read-only inspection).
    - Không tự động chạy lúc import module.
    - Không chặn ứng dụng khởi động nếu DB offline.
    """
    eng = target_engine or engine
    return verify_schema(eng)
