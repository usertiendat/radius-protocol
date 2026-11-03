from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

try:
    from app.core.dependencies import get_db
    from app.core.exceptions import BaseBusinessException
    from app.schemas.user import UserCreate, UserResponse, UserUpdate
    from app.services.user_service import UserService
except ImportError:
    from core.dependencies import get_db
    from core.exceptions import BaseBusinessException
    from schemas.user import UserCreate, UserResponse, UserUpdate
    from services.user_service import UserService

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


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
def create_user(data: UserCreate, db: Session = Depends(get_db)) -> UserResponse:
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
    db: Session = Depends(get_db),
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
def delete_user(username: str, db: Session = Depends(get_db)) -> Response:
    try:
        UserService(db).delete_user(username)
    except BaseBusinessException as error:
        _raise_http_error(error)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
