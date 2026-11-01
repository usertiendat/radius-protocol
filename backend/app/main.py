from fastapi import FastAPI, HTTPException, status

try:
    from app.schemas import LoginRequest, LoginResponse
    from app.radius_auth import (
        authenticate_radius,
        RadiusAuthenticationFailed,
        RadiusConnectionError,
        RadiusConfigError,
        RadiusError,
    )
except ImportError:
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


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "radius-backend",
    }


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
