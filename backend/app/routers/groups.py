from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

try:
    from app.core.dependencies import get_db
    from app.core.exceptions import BaseBusinessException
    from app.schemas.group import GroupCreate, GroupResponse, GroupUpdate
    from app.services.group_service import GroupService
except ImportError:
    from core.dependencies import get_db
    from core.exceptions import BaseBusinessException
    from schemas.group import GroupCreate, GroupResponse, GroupUpdate
    from services.group_service import GroupService

router = APIRouter(prefix="/api/v1/groups", tags=["Groups"])


def _raise_http_error(error: BaseBusinessException) -> NoReturn:
    raise HTTPException(
        status_code=error.http_status,
        detail=error.message,
    ) from error


@router.get("", response_model=list[GroupResponse], summary="Lấy danh sách group")
def get_groups(db: Session = Depends(get_db)) -> list[GroupResponse]:
    return GroupService(db).get_groups()


@router.post(
    "",
    response_model=GroupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Tạo group",
)
def create_group(data: GroupCreate, db: Session = Depends(get_db)) -> GroupResponse:
    try:
        return GroupService(db).create_group(data)
    except BaseBusinessException as error:
        _raise_http_error(error)


@router.put(
    "/{groupname}",
    response_model=GroupResponse,
    summary="Cập nhật group",
)
def update_group(
    groupname: str,
    data: GroupUpdate,
    db: Session = Depends(get_db),
) -> GroupResponse:
    try:
        return GroupService(db).update_group(groupname, data)
    except BaseBusinessException as error:
        _raise_http_error(error)


@router.delete(
    "/{groupname}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Xóa group",
)
def delete_group(groupname: str, db: Session = Depends(get_db)) -> Response:
    try:
        GroupService(db).delete_group(groupname)
    except BaseBusinessException as error:
        _raise_http_error(error)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{groupname}",
    response_model=GroupResponse,
    summary="Lấy thông tin group",
)
def get_group_by_name(
    groupname: str,
    db: Session = Depends(get_db),
) -> GroupResponse:
    try:
        return GroupService(db).get_group_by_name(groupname)
    except BaseBusinessException as error:
        _raise_http_error(error)
