"""Administrator login endpoint for the web dashboard."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.dependencies import get_db
from app.core.exceptions import UnauthorizedError
from app.core.security import TokenConfigError
from app.schemas.admin import AdminLoginRequest, AdminLoginResponse
from app.services.admin_auth_service import AdminAuthService
from app.core.config import settings

router = APIRouter(prefix="/api/v1/admin/auth", tags=["Admin Authentication"])


@router.post("/login", response_model=AdminLoginResponse)
def admin_login(request: AdminLoginRequest, db: Session = Depends(get_db)):
    try:
        _, token = AdminAuthService(db).authenticate(
            request.username, request.password
        )
    except UnauthorizedError as exc:
        raise HTTPException(status_code=exc.http_status, detail=exc.message) from exc
    except TokenConfigError as exc:
        raise HTTPException(
            status_code=503,
            detail="Dịch vụ đăng nhập Admin chưa được cấu hình an toàn.",
        ) from exc
    return AdminLoginResponse(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
