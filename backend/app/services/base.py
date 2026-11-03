"""
Base Service Layer cho RADIUS Enterprise Authentication & Access Control.
Định nghĩa quy ước nền tảng cho toàn bộ các Service trong tương lai:
1. Nhận SQLAlchemy Session từ bên ngoài (thông qua Dependency Injection từ router).
2. Tuyệt đối không tự ý khởi tạo Engine hoặc SessionLocal.
3. Hoàn toàn độc lập với HTTP Transport (không phụ thuộc FastAPI Request/Response).
4. Không triển khai abstraction hoặc repository pattern dư thừa.
"""

from sqlalchemy.orm import Session


class BaseService:
    """
    Lớp cơ sở cho toàn bộ các Service nghiệp vụ.

    Nguyên tắc cốt lõi:
    - Session Injection: Mọi thao tác đều dùng session được truyền từ ngoài vào.
    - No Engine Creation: Không bao giờ tự mở kết nối hay tạo session factory riêng.
    - Transport Agnostic: Không dính dáng đến FastAPI request/response headers hay cookies.
    """

    def __init__(self, db: Session) -> None:
        if not isinstance(db, Session):
            raise TypeError("Tham số 'db' phải là một instance hợp lệ của sqlalchemy.orm.Session")
        self.db = db
