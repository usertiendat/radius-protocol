"""HTTP endpoints for accounting and authentication monitoring."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.auth import get_current_admin
from app.core.dependencies import get_db
from app.models.application import AppAdmin
from app.services.accounting_service import AccountingService

router = APIRouter(prefix="/api/v1", tags=["Accounting & Logs"])


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
    return AccountingService(db).get_dashboard_summary()
