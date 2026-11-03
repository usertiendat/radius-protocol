import os
from pathlib import Path
from typing import Optional
from urllib.parse import quote_plus

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Đường dẫn thư mục gốc của dự án (Radius-Protocol)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
ENV_PATH = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """
    Cấu hình ứng dụng tập trung quản trị qua biến môi trường (.env).
    Kế thừa pydantic_settings.BaseSettings để tự động validate kiểu dữ liệu.
    """
    model_config = SettingsConfigDict(
        env_file=(str(ENV_PATH), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Cấu hình Ứng dụng
    APP_NAME: str = Field(
        default="RADIUS Network Access Management",
        description="Tên ứng dụng",
    )
    APP_VERSION: str = Field(
        default="0.2.0",
        description="Phiên bản hệ thống",
    )
    DEBUG: bool = Field(
        default=False,
        description="Chế độ debug",
    )

    # Cấu hình Bảo mật & JWT
    JWT_SECRET_KEY: str = Field(
        default="",
        description="Khóa bí mật ký JWT Token (phải thiết lập trong production)",
    )
    JWT_ALGORITHM: str = Field(
        default="HS256",
        description="Thuật toán mã hóa JWT",
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30,
        ge=1,
        description="Thời hạn sống của Access Token tính theo phút",
    )

    # Cấu hình Cơ sở dữ liệu MariaDB
    DB_HOST: str = Field(
        default="localhost",
        description="Địa chỉ máy chủ MariaDB",
    )
    DB_PORT: int = Field(
        default=3306,
        description="Cổng dịch vụ MariaDB",
    )
    DB_NAME: str = Field(
        default="radius_db",
        description="Tên cơ sở dữ liệu",
    )
    DB_USER: str = Field(
        default="root",
        description="Tài khoản kết nối cơ sở dữ liệu",
    )
    DB_PASSWORD: str = Field(
        default="",
        description="Mật khẩu kết nối cơ sở dữ liệu",
    )
    DATABASE_URL: Optional[str] = Field(
        default=None,
        description="URL kết nối SQLAlchemy hoàn chỉnh (nếu được khai báo sẽ ưu tiên)",
    )

    # Cấu hình Máy chủ FreeRADIUS (Tương thích 100% với các biến môi trường hiện hữu)
    RADIUS_SERVER: str = Field(
        default="127.0.0.1",
        description="Địa chỉ IP hoặc hostname của máy chủ FreeRADIUS",
    )
    RADIUS_AUTH_PORT: int = Field(
        default=1812,
        description="Cổng xác thực RADIUS UDP",
    )
    RADIUS_ACCT_PORT: int = Field(
        default=1813,
        description="Cổng nhật ký phiên (Accounting) RADIUS UDP",
    )
    RADIUS_SECRET: str = Field(
        default="",
        description="Shared secret trao đổi giữa client và FreeRADIUS",
    )
    RADIUS_TIMEOUT: int = Field(
        default=3,
        ge=1,
        description="Thời gian chờ phản hồi tối đa (giây)",
    )
    RADIUS_RETRIES: int = Field(
        default=1,
        ge=0,
        description="Số lần thử gửi lại gói tin khi timeout",
    )

    @property
    def database_url(self) -> str:
        """
        Tạo chuỗi kết nối chuẩn SQLAlchemy cho MariaDB qua driver PyMySQL.
        Tự động mã hóa mật khẩu để tránh lỗi ký tự đặc biệt trong URL.
        """
        if self.DATABASE_URL:
            return self.DATABASE_URL

        encoded_password = quote_plus(self.DB_PASSWORD) if self.DB_PASSWORD else ""
        credentials = f"{self.DB_USER}:{encoded_password}" if self.DB_USER else self.DB_USER
        return f"mysql+pymysql://{credentials}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}?charset=utf8mb4"

    def __repr__(self) -> str:
        """Che giấu toàn bộ thông tin nhạy cảm khi in đối tượng Settings."""
        return (
            f"<Settings(APP_NAME='{self.APP_NAME}', "
            f"DB_HOST='{self.DB_HOST}', DB_PORT={self.DB_PORT}, DB_NAME='{self.DB_NAME}', "
            f"RADIUS_SERVER='{self.RADIUS_SERVER}', RADIUS_AUTH_PORT={self.RADIUS_AUTH_PORT}, "
            f"JWT_ALGORITHM='{self.JWT_ALGORITHM}')>"
        )

    def __str__(self) -> str:
        return self.__repr__()


# Khởi tạo đối tượng cấu hình duy nhất dùng cho toàn ứng dụng
settings = Settings()
