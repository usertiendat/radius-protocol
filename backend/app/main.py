from pathlib import Path
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse

try:
    from app.core.exception_handlers import register_exception_handlers
    from app.routers.accounting import router as accounting_router
    from app.routers.admin_auth import router as admin_auth_router
    from app.routers.groups import router as groups_router
    from app.routers.health import (
        database_health,
        health_check,
        router as health_router,
    )
    from app.routers.users import router as users_router
    from app.schemas import LoginRequest, LoginResponse
    from app.radius_auth import (
        authenticate_radius,
        RadiusAuthenticationFailed,
        RadiusConnectionError,
        RadiusConfigError,
        RadiusError,
    )
except ImportError:
    from core.exception_handlers import register_exception_handlers
    from routers.accounting import router as accounting_router
    from routers.admin_auth import router as admin_auth_router
    from routers.groups import router as groups_router
    from routers.health import (
        database_health,
        health_check,
        router as health_router,
    )
    from routers.users import router as users_router
    from schemas import LoginRequest, LoginResponse
    from radius_auth import (
        authenticate_radius,
        RadiusAuthenticationFailed,
        RadiusConnectionError,
        RadiusConfigError,
        RadiusError,
    )

app = FastAPI(
    title="RADIUS Network Access Management",
    description="API quản lý xác thực và giám sát truy cập mạng",
    version="0.1.0",
)

# Đăng ký Global Exception Handlers (Phase 0B - Step 3.3.3)
register_exception_handlers(app)

# Đăng ký các API Routers
app.include_router(health_router)
app.include_router(admin_auth_router)
app.include_router(accounting_router)
app.include_router(users_router)
app.include_router(groups_router)

# Phục vụ giao diện Dashboard
_DASHBOARD_FILE = Path(__file__).resolve().parent / "static" / "dashboard.html"


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
@app.get("/static/dashboard.html", include_in_schema=False)
def dashboard():
    """Phục vụ trang web Dashboard quản trị & giám sát hệ thống."""
    return FileResponse(_DASHBOARD_FILE)


@app.post(
    "/auth/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Đăng nhập xác thực qua máy chủ RADIUS",
)
def login(request: LoginRequest):
    """
    Xác thực người dùng qua FreeRADIUS bằng giao thức RADIUS (PAP).

    Sử dụng endpoint đồng bộ (def) để FastAPI tự động điều phối qua worker threadpool,
    tránh làm nghẽn Event Loop khi thực hiện socket network I/O.
    """
    try:
        authenticate_radius(request.username, request.password)
        return LoginResponse(
            success=True,
            message="Xác thực thành công.",
        )
    except RadiusAuthenticationFailed:
        # Chỉ duy nhất Access-Reject từ FreeRADIUS mới rơi vào đây
        raise HTTPException(
              status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tên đăng nhập hoặc mật khẩu không hợp lệ.",
        )
    except (RadiusConnectionError, RadiusConfigError, RadiusError):
        # Timeout, lỗi socket, mất kết nối mạng hoặc lỗi cấu hình hệ thống
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dịch vụ xác thực hiện không khả dụng.",
        )
