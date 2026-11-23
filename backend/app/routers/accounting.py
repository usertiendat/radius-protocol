<<<<<<< HEAD
"""HTTP endpoints for accounting and authentication monitoring."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.auth import get_current_admin
from app.core.dependencies import get_db
from app.models.application import AppAdmin
from app.services.accounting_service import AccountingService
=======
"""
HTTP endpoints cho Accounting, giám sát phiên kết nối mạng và nhật ký xác thực.
Sử dụng AccountingService để thực hiện các truy vấn ORM thuần đọc, bảo đảm an toàn dữ liệu.
Bảo vệ bằng RBAC: Yêu cầu quyền đọc quản trị viên (superadmin, it_admin, auditor).
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

try:
    from app.core.admin_dependencies import CurrentAdmin
    from app.core.rbac import AdminRole, require_roles
    from app.database import get_db
    from app.services.accounting_service import AccountingService
except ImportError:
    from core.admin_dependencies import CurrentAdmin
    from core.rbac import AdminRole, require_roles
    from database import get_db
    from services.accounting_service import AccountingService
>>>>>>> staging

router = APIRouter(prefix="/api/v1", tags=["Accounting & Monitoring"])

<<<<<<< HEAD

@router.get("/accounting/sessions")
def get_accounting_sessions(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: AppAdmin = Depends(get_current_admin),
):
    return AccountingService(db).list_sessions(skip=skip, limit=limit)


@router.get("/accounting/sessions/online")
def get_online_sessions(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: AppAdmin = Depends(get_current_admin),
):
    return AccountingService(db).list_online_sessions(limit=limit)


@router.get("/accounting/sessions/{session_id}")
def get_accounting_session_by_id(
    session_id: int,
    db: Session = Depends(get_db),
    _: AppAdmin = Depends(get_current_admin),
):
    session = AccountingService(db).get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.get("/accounting/statistics")
def get_accounting_statistics(
    db: Session = Depends(get_db),
    _: AppAdmin = Depends(get_current_admin),
):
    return AccountingService(db).get_statistics()


@router.get("/accounting/session-trend")
def get_accounting_session_trend(
    days: int = Query(default=7, ge=1, le=30),
    db: Session = Depends(get_db),
    _: AppAdmin = Depends(get_current_admin),
):
    return AccountingService(db).get_session_trend(days=days)


@router.get("/logs/authentication")
@router.get("/monitoring/logs")
def get_auth_logs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _: AppAdmin = Depends(get_current_admin),
):
    return AccountingService(db).list_auth_logs(skip=skip, limit=limit)


@router.get("/dashboard/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db),
    _: AppAdmin = Depends(get_current_admin),
):
=======
READ_ROLES = (AdminRole.SUPERADMIN, AdminRole.IT_ADMIN, AdminRole.AUDITOR)
require_accounting_read = require_roles(*READ_ROLES)


@router.get(
    "/accounting/sessions",
    summary="Lấy danh sách các phiên kết nối mạng (phân trang, sắp xếp mới nhất)",
)
def get_accounting_sessions(
    skip: int = Query(default=0, ge=0, description="Số lượng bản ghi bỏ qua"),
    limit: int = Query(default=100, ge=1, le=500, description="Số lượng bản ghi tối đa"),
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(require_accounting_read),
):
    """Truy vấn danh sách lịch sử phiên kết nối radacct."""
    return AccountingService(db).list_sessions(skip=skip, limit=limit)


@router.get(
    "/accounting/sessions/online",
    summary="Lấy danh sách các phiên kết nối đang hoạt động (Online)",
)
def get_online_sessions(
    limit: int = Query(default=100, ge=1, le=500, description="Số lượng bản ghi tối đa"),
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(require_accounting_read),
):
    """Truy vấn danh sách phiên mạng đang online (acctstoptime IS NULL)."""
    return AccountingService(db).list_online_sessions(limit=limit)


@router.get(
    "/accounting/sessions/{session_id}",
    summary="Lấy chi tiết một phiên kết nối theo radacctid",
)
def get_accounting_session_by_id(
    session_id: int,
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(require_accounting_read),
):
    """Truy vấn thông tin chi tiết một phiên radacct."""
    session = AccountingService(db).get_session(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )
    return session


@router.get(
    "/accounting/statistics",
    summary="Thống kê tổng hợp: active sessions, tổng thời lượng và lưu lượng",
)
def get_accounting_statistics(
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(require_accounting_read),
):
    """Tính toán thống kê phiên kết nối từ radacct."""
    return AccountingService(db).get_statistics()


@router.get(
    "/accounting/session-trend",
    summary="Lấy thống kê xu hướng phiên kết nối theo ngày (mặc định 7 ngày)",
)
def get_accounting_session_trend(
    days: int = Query(default=7, ge=1, le=30, description="Số ngày thống kê"),
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(require_accounting_read),
):
    """Lấy số lượng phiên kết nối theo từng ngày phục vụ vẽ biểu đồ."""
    return AccountingService(db).get_session_trend(days=days)


@router.get(
    "/logs/authentication",
    summary="Lấy danh sách nhật ký xác thực RADIUS gần đây (không lộ password)",
)
@router.get(
    "/monitoring/logs",
    summary="Alias lấy danh sách nhật ký xác thực RADIUS",
    include_in_schema=False,
)
def get_auth_logs(
    skip: int = Query(default=0, ge=0, description="Số lượng bản ghi bỏ qua"),
    limit: int = Query(default=50, ge=1, le=500, description="Số lượng bản ghi tối đa"),
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(require_accounting_read),
):
    """Truy vấn lịch sử xác thực radpostauth (Access-Accept / Access-Reject)."""
    return AccountingService(db).list_auth_logs(skip=skip, limit=limit)


@router.get(
    "/dashboard/summary",
    summary="Lấy dữ liệu tổng quan cho trang Dashboard giám sát",
)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_admin: CurrentAdmin = Depends(require_accounting_read),
):
    """
    Thống kê tổng số người dùng, thiết bị NAS, phiên đang hoạt động,
    và số lượt xác thực thành công/thất bại hôm nay.
    """
>>>>>>> staging
    return AccountingService(db).get_dashboard_summary()
