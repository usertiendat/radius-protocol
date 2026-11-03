"""
Database Engine và Session Management cho RADIUS Management Backend.
Sử dụng SQLAlchemy 2.x với kết nối lazy pooling qua PyMySQL.
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


# Định nghĩa Declarative Base chuẩn SQLAlchemy 2.x
class Base(DeclarativeBase):
    """Lớp cơ sở cho toàn bộ các ORM models trong ứng dụng."""
    pass


# Khởi tạo Engine ở chế độ lazy (không mở socket kết nối mạng khi import module)
# pool_pre_ping=True: Tự động kiểm tra tính sống còn của connection trước khi dùng
# pool_recycle=3600: Tái tạo kết nối sau 1 giờ để tránh MariaDB 'MySQL server has gone away'
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_recycle=3600,
    pool_size=10,
    max_overflow=20,
)

# Cấu hình Session Factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI Dependency Generator quản lý vòng đời của Database Session.
    Bảo đảm session luôn được đóng an toàn trong khối finally sau mỗi HTTP request.
    Nếu xảy ra exception trong quá trình request, tự động rollback transaction.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
