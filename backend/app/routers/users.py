from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

try:
    from app.core.admin_dependencies import CurrentAdmin
    from app.core.dependencies import get_db, get_write_db
    from app.core.exceptions import BaseBusinessException
    from app.core.rbac import AdminRole, require_roles
    from app.schemas.user import UserCreate, UserResponse, UserUpdate
    from app.services.user_service import UserService
except ImportError:
    from core.admin_dependencies import CurrentAdmin
    from core.dependencies import get_db, get_write_db
    from core.exceptions import BaseBusinessException
    from core.rbac import AdminRole, require_roles
    from schemas.user import UserCreate, UserResponse, UserUpdate
    from services.user_service import UserService

router = APIRouter(prefix="/api/v1/users", tags=["Users"])

READ_ROLES = (AdminRole.SUPERADMIN, AdminRole.IT_ADMIN, AdminRole.AUDITOR)
WRITE_ROLES = (AdminRole.SUPERADMIN, AdminRole.IT_ADMIN)

require_user_read = require_roles(*READ_ROLES)
require_user_write = require_roles(*WRITE_ROLES)


def _raise_http_error(error: BaseBusinessException) -> NoReturn:
    raise HTTPException(
        status_code=error.http_status,
        detail=error.message,
    ) from error


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Tạo người dùng",
)
def create_user(
    data: UserCreate,
    current_admin: CurrentAdmin = Depends(require_user_write),
    db: Session = Depends(get_write_db),
) -> UserResponse:
    try:
        return UserService(db).create_user(data)
    except BaseBusinessException as error:
        _raise_http_error(error)


@router.get(
    "",
    response_model=list[UserResponse],
    summary="Lấy danh sách người dùng",
)
def get_users(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1),
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(require_user_read),
) -> list[UserResponse]:
    return UserService(db).get_users(skip=skip, limit=limit)


@router.get(
    "/{username}",
    response_model=UserResponse,
    summary="Lấy thông tin người dùng",
)
def get_user_by_username(
    username: str,
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(require_user_read),
) -> UserResponse:
    try:
        return UserService(db).get_user_by_username(username)
    except BaseBusinessException as error:
        _raise_http_error(error)


@router.put(
    "/{username}",
    response_model=UserResponse,
    summary="Cập nhật người dùng",
)
def update_user(
    username: str,
    data: UserUpdate,
    current_admin: CurrentAdmin = Depends(require_user_write),
    db: Session = Depends(get_write_db),
) -> UserResponse:
    try:
        return UserService(db).update_user(username, data)
    except BaseBusinessException as error:
        _raise_http_error(error)


@router.delete(
    "/{username}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Xóa người dùng",
)
def delete_user(
    username: str,
    current_admin: CurrentAdmin = Depends(require_user_write),
    db: Session = Depends(get_write_db),
) -> Response:
    try:
        UserService(db).delete_user(username)
    except BaseBusinessException as error:
        _raise_http_error(error)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
