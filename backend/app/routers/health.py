"""
Health Monitoring Router cho RADIUS Management Backend.
Cung cấp:
- GET /health: Giám sát trạng thái hoạt động của FastAPI Backend (độc lập hoàn toàn với MariaDB).
- GET /health/database: Giám sát trạng thái kết nối CSDL MariaDB thông qua check_database_connection().
"""

from fastapi import APIRouter, Response, status

try:
    from app.core.dependencies import check_database_connection
except ImportError:
    from core.dependencies import check_database_connection

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Kiểm tra trạng thái hoạt động của FastAPI Backend",
)
def health_check():
    """
    Kiểm tra ứng dụng FastAPI đang hoạt động bình thường.
    Endpoint này hoàn toàn độc lập với MariaDB (không phụ thuộc và không thực hiện SQL query).
    """
    return {
        "status": "healthy",
        "service": "radius-backend",
    }


@router.get(
    "/health/database",
    status_code=status.HTTP_200_OK,
    summary="Kiểm tra trạng thái kết nối Cơ sở dữ liệu MariaDB",
)
def database_health(response: Response):
    """
    Kiểm tra trạng thái kết nối MariaDB on-demand.
    - HTTP 200: Kết nối thành công, CSDL khả dụng.
    - HTTP 503: Kết nối thất bại, CSDL offline hoặc không thể kết nối.

    Yêu cầu bảo mật:
    - Tuyệt đối không trả về database URL, username, password hay credentials.
    - Tuyệt đối không trả về raw SQLAlchemy exception hay stack trace.
    - Không retry vô hạn và không thực hiện DDL.
    """
    is_healthy, _ = check_database_connection()
    if is_healthy:
        return {
            "status": "healthy",
            "service": "database",
        }

    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "unavailable",
        "service": "database",
        "message": "Database connection is unavailable",
    }
