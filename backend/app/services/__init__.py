"""
Services Package cho RADIUS Enterprise Authentication & Access Control.
Chịu trách nhiệm thực thi toàn bộ Business Logic của hệ thống.

Quy ước chuẩn của Service Layer (Service Layer Contract):
1. Nhận SQLAlchemy Session từ bên ngoài thông qua Dependency Injection (db: Session).
2. Tuyệt đối không tự ý khởi tạo Engine hoặc SessionLocal nội bộ.
3. Hoàn toàn độc lập với HTTP Transport (không nhận/trả trực tiếp FastAPI Request/Response).
4. Quản lý transaction rõ ràng (commit/rollback) theo từng nghiệp vụ cụ thể.
5. Không trả về raw SQLAlchemy exception cho Client; chuyển hóa thành Business Exception.
6. Không triển khai abstraction hoặc repository pattern dư thừa nếu chưa có nhu cầu thực tế.
"""

from app.services.base import BaseService
from app.services.transaction import transactional

__all__ = ["BaseService", "transactional"]
