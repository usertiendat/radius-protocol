"""
Hệ thống Business Exceptions cho RADIUS Management Backend.
Chịu trách nhiệm:
- Cung cấp các ngoại lệ nghiệp vụ độc lập hoàn toàn với FastAPI và tầng HTTP transport.
- Lưu giữ error code và HTTP status metadata phục vụ tầng Router ánh xạ response.
- Tuyệt đối không chứa thông tin nhạy cảm (database credentials, stack trace) trong message.
"""

from typing import Optional


class BaseBusinessException(Exception):
    """
    Ngoại lệ cơ sở cho toàn bộ các ngoại lệ nghiệp vụ trong hệ thống.
    Độc lập hoàn toàn với FastAPI / Starlette HTTPException.
    """

    default_code: str = "BUSINESS_ERROR"
    default_message: str = "Đã xảy ra lỗi nghiệp vụ trong hệ thống."
    http_status: int = 400

    def __init__(
        self,
        message: Optional[str] = None,
        code: Optional[str] = None,
    ) -> None:
        self.message = message or self.default_message
        self.code = code or self.default_code
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(code='{self.code}', message='{self.message}', http_status={self.http_status})"


class NotFoundError(BaseBusinessException):
    """Ngoại lệ khi không tìm thấy tài nguyên nghiệp vụ yêu cầu (HTTP 404)."""

    default_code: str = "RESOURCE_NOT_FOUND"
    default_message: str = "Tài nguyên được yêu cầu không tồn tại."
    http_status: int = 404


class ConflictError(BaseBusinessException):
    """Ngoại lệ khi tài nguyên đã tồn tại hoặc xảy ra xung đột dữ liệu nghiệp vụ (HTTP 409)."""

    default_code: str = "RESOURCE_CONFLICT"
    default_message: str = "Tài nguyên đã tồn tại hoặc xảy ra xung đột dữ liệu."
    http_status: int = 409


class UnauthorizedError(BaseBusinessException):
    """Ngoại lệ khi yêu cầu xác thực không hợp lệ hoặc thiếu thông tin định danh (HTTP 401)."""

    default_code: str = "UNAUTHORIZED"
    default_message: str = "Yêu cầu xác thực hợp lệ để truy cập tài nguyên này."
    http_status: int = 401


class ForbiddenError(BaseBusinessException):
    """Ngoại lệ khi đối tượng không đủ thẩm quyền để thực hiện hành động (HTTP 403)."""

    default_code: str = "FORBIDDEN"
    default_message: str = "Bạn không có quyền truy cập hoặc thực hiện thao tác này."
    http_status: int = 403


class ServiceUnavailableError(BaseBusinessException):
    """Ngoại lệ khi một dịch vụ phụ thuộc (CSDL, RADIUS) tạm thời không khả dụng (HTTP 503)."""

    default_code: str = "SERVICE_UNAVAILABLE"
    default_message: str = "Dịch vụ hiện không khả dụng, vui lòng thử lại sau."
    http_status: int = 503


class ValidationError(BaseBusinessException):
    """
    Ngoại lệ kiểm tra dữ liệu nghiệp vụ không thỏa mãn quy tắc hệ thống (HTTP 422).
    Lưu ý: Phân biệt với Pydantic ValidationError (vốn chỉ validate schema cú pháp).
    """

    default_code: str = "VALIDATION_ERROR"
    default_message: str = "Dữ liệu không thỏa mãn quy tắc nghiệp vụ của hệ thống."
    http_status: int = 422


# Alias để tránh nhầm lẫn với pydantic.ValidationError khi cần
BusinessValidationError = ValidationError
