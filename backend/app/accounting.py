from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

router = APIRouter(prefix="/api/v1", tags=["Accounting & Logs"])

# API 1: Lấy danh sách lịch sử các phiên truy cập từ bảng radacct
@router.get("/accounting/sessions")
def get_accounting_sessions(skip: int = 0, limit: int = 100, db: Session = Depends()):
    query = text("""
        SELECT 
            radacctid, username, nasipaddress, acctstarttime, 
            acctstoptime, acctsessiontime, acctinputoctets, acctoutputoctets, acctterminatecause
        FROM radacct 
        ORDER BY acctstarttime DESC 
        LIMIT :limit OFFSET :skip
    """)
    result = db.execute(query, {"limit": limit, "skip": skip}).mappings().all()
    return list(result)

# API 2: Lấy lịch sử xác thực từ bảng radpostauth
@router.get("/logs/authentication")
def get_auth_logs(skip: int = 0, limit: int = 50, db: Session = Depends()):
    query = text("""
        SELECT id, username, pass, reply, authdate 
        FROM radpostauth 
        ORDER BY authdate DESC 
        LIMIT :limit OFFSET :skip
    """)
    result = db.execute(query, {"limit": limit, "skip": skip}).mappings().all()
    return list(result)

# API 3: Thống kê tổng quan cho Dashboard
@router.get("/dashboard/summary")
def get_dashboard_summary(db: Session = Depends()):
    total_sessions = db.execute(text("SELECT COUNT(*) FROM radacct")).scalar()
    active_sessions = db.execute(text("SELECT COUNT(*) FROM radacct WHERE acctstoptime IS NULL")).scalar()
    
    return {
        "total_sessions": total_sessions,
        "active_sessions": active_sessions
    }