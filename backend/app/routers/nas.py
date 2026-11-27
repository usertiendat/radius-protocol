from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

try:
    from app.core.admin_dependencies import CurrentAdmin, get_current_admin
    from app.core.dependencies import get_db, get_write_db
    from app.core.exceptions import BaseBusinessException
    from app.core.rbac import AdminRole, require_roles
    from app.schemas.nas import NASCreate, NASResponse, NASUpdate
    from app.services.nas_service import NASService
except ImportError:
    from core.admin_dependencies import CurrentAdmin, get_current_admin
    from core.dependencies import get_db, get_write_db
    from core.exceptions import BaseBusinessException
    from core.rbac import AdminRole, require_roles
    from schemas.nas import NASCreate, NASResponse, NASUpdate
    from services.nas_service import NASService

router = APIRouter(prefix="/api/v1/nas", tags=["NAS"])

READ_ROLES = (AdminRole.SUPERADMIN, AdminRole.IT_ADMIN, AdminRole.AUDITOR)
WRITE_ROLES = (AdminRole.SUPERADMIN, AdminRole.IT_ADMIN)

require_nas_read = require_roles(*READ_ROLES)
require_nas_write = require_roles(*WRITE_ROLES)


def _raise_http_error(error: BaseBusinessException) -> NoReturn:
    raise HTTPException(
        status_code=error.http_status,
        detail=error.message,
    ) from error


@router.get(
    "",
    response_model=list[NASResponse],
    summary="Lấy danh sách thiết bị NAS",
    dependencies=[Depends(require_nas_read)],
)
def get_nas_list(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1),
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(get_current_admin),
) -> list[NASResponse]:
    return NASService(db).get_nas_list(skip=skip, limit=limit)


@router.post(
    "",
    response_model=NASResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Thêm thiết bị NAS",
    dependencies=[Depends(require_nas_write)],
)
def create_nas(
    data: NASCreate,
    current_admin: CurrentAdmin = Depends(get_current_admin),
    db: Session = Depends(get_write_db),
) -> NASResponse:
    try:
        return NASService(db).create_nas(data)
    except BaseBusinessException as error:
        _raise_http_error(error)


@router.get(
    "/{nas_id}",
    response_model=NASResponse,
    summary="Lấy thông tin thiết bị NAS",
    dependencies=[Depends(require_nas_read)],
)
def get_nas_by_id(
    nas_id: int,
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(get_current_admin),
) -> NASResponse:
    try:
        return NASService(db).get_nas_by_id(nas_id)
    except BaseBusinessException as error:
        _raise_http_error(error)


@router.put(
    "/{nas_id}",
    response_model=NASResponse,
    summary="Cập nhật thiết bị NAS",
    dependencies=[Depends(require_nas_write)],
)
def update_nas(
    nas_id: int,
    data: NASUpdate,
    current_admin: CurrentAdmin = Depends(get_current_admin),
    db: Session = Depends(get_write_db),
) -> NASResponse:
    try:
        return NASService(db).update_nas(nas_id, data)
    except BaseBusinessException as error:
        _raise_http_error(error)


@router.delete(
    "/{nas_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Xóa thiết bị NAS",
    dependencies=[Depends(require_nas_write)],
)
def delete_nas(
    nas_id: int,
    current_admin: CurrentAdmin = Depends(get_current_admin),
    db: Session = Depends(get_write_db),
) -> Response:
    try:
        NASService(db).delete_nas(nas_id)
    except BaseBusinessException as error:
        _raise_http_error(error)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
