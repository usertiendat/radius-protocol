"""
SQLAlchemy ORM Models cho 2 bảng quản trị ứng dụng:
- app_admins: Quản trị viên đăng nhập Dashboard.
- app_users: Hồ sơ người dùng mạng mở rộng (Metadata Profile).
"""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from app.database import Base


class AppAdmin(Base):
    """
    Bảng app_admins: Quản trị viên ứng dụng Dashboard.
    Đăng nhập trực tiếp qua FastAPI HTTP, không qua FreeRADIUS.
    Mật khẩu băm an toàn bằng PBKDF2-HMAC-SHA256 (từ core/security.py).
    """
    __tablename__ = "app_admins"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    email = Column(String(255), nullable=True)
    role = Column(String(32), nullable=False, default="it_admin")  # superadmin, it_admin, auditor
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class AppUser(Base):
    """
    Bảng app_users: Hồ sơ định danh mở rộng của người dùng mạng.
    Lưu ý kiến trúc: Bảng này TUYỆT ĐỐI KHÔNG lưu trường password hoặc password_hash.
    Mật khẩu mạng thuộc quyền quản lý của FreeRADIUS và lưu tại bảng radcheck.
    Không có bất kỳ quan hệ cascade delete nào làm mất lịch sử radacct hay radpostauth.
    """
    __tablename__ = "app_users"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    full_name = Column(String(128), nullable=True)
    email = Column(String(255), nullable=True)
    phone = Column(String(32), nullable=True)
    group_name = Column(String(64), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
