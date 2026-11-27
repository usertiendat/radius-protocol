from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

try:
    from app.core.admin_dependencies import CurrentAdmin, get_current_admin
    from app.core.dependencies import get_db, get_write_db
    from app.core.exceptions import BaseBusinessException
    from app.core.rbac import AdminRole, require_roles
    from app.schemas.group import GroupCreate, GroupResponse, GroupUpdate
    from app.services.group_service import GroupService
except ImportError:
    from core.admin_dependencies import CurrentAdmin, get_current_admin
    from core.dependencies import get_db, get_write_db
    from core.exceptions import BaseBusinessException
    from core.rbac import AdminRole, require_roles
    from schemas.group import GroupCreate, GroupResponse, GroupUpdate
    from services.group_service import GroupService

router = APIRouter(prefix="/api/v1/groups", tags=["Groups"])

READ_ROLES = (AdminRole.SUPERADMIN, AdminRole.IT_ADMIN, AdminRole.AUDITOR)
WRITE_ROLES = (AdminRole.SUPERADMIN, AdminRole.IT_ADMIN)

require_group_read = require_roles(*READ_ROLES)
require_group_write = require_roles(*WRITE_ROLES)


def _raise_http_error(error: BaseBusinessException) -> NoReturn:
    raise HTTPException(
        status_code=error.http_status,
        detail=error.message,
    ) from error


@router.get(
    "",
    response_model=list[GroupResponse],
    summary="Lấy danh sách group",
    dependencies=[Depends(require_group_read)],
)
def get_groups(
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(get_current_admin),
) -> list[GroupResponse]:
    return GroupService(db).get_groups()


@router.post(
    "",
    response_model=GroupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Tạo group",
    dependencies=[Depends(require_group_write)],
)
def create_group(
    data: GroupCreate,
    current_admin: CurrentAdmin = Depends(get_current_admin),
    db: Session = Depends(get_write_db),
) -> GroupResponse:
    try:
        return GroupService(db).create_group(data)
    except BaseBusinessException as error:
        _raise_http_error(error)


@router.put(
    "/{groupname}",
    response_model=GroupResponse,
    summary="Cập nhật group",
    dependencies=[Depends(require_group_write)],
)
def update_group(
    groupname: str,
    data: GroupUpdate,
    current_admin: CurrentAdmin = Depends(get_current_admin),
    db: Session = Depends(get_write_db),
) -> GroupResponse:
    try:
        return GroupService(db).update_group(groupname, data)
    except BaseBusinessException as error:
        _raise_http_error(error)


@router.delete(
    "/{groupname}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Xóa group",
    dependencies=[Depends(require_group_write)],
)
def delete_group(
    groupname: str,
    current_admin: CurrentAdmin = Depends(get_current_admin),
    db: Session = Depends(get_write_db),
) -> Response:
    try:
        GroupService(db).delete_group(groupname)
    except BaseBusinessException as error:
        _raise_http_error(error)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{groupname}",
    response_model=GroupResponse,
    summary="Lấy thông tin group",
    dependencies=[Depends(require_group_read)],
)
def get_group_by_name(
    groupname: str,
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(get_current_admin),
) -> GroupResponse:
    try:
        return GroupService(db).get_group_by_name(groupname)
    except BaseBusinessException as error:
        _raise_http_error(error)
