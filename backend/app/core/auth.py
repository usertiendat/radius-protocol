"""JWT authentication dependencies for protected administrator APIs."""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.dependencies import get_db
from app.core.exceptions import UnauthorizedError
from app.core.security import (
    TokenConfigError,
    TokenExpiredError,
    TokenInvalidError,
    verify_access_token,
)
from app.models.application import AppAdmin
from app.services.admin_auth_service import AdminAuthService

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AppAdmin:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cần đăng nhập Admin để tiếp tục.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = verify_access_token(credentials.credentials)
        username = payload.get("sub")
        if payload.get("token_type") != "admin" or not isinstance(username, str):
            raise TokenInvalidError("Token không có định danh Admin hợp lệ.")
        return AdminAuthService(db).get_active_admin(username)
    except (TokenExpiredError, TokenInvalidError, UnauthorizedError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token không hợp lệ hoặc đã hết hạn. Vui lòng đăng nhập lại.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except TokenConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dịch vụ xác thực Admin chưa được cấu hình an toàn.",
        ) from exc
