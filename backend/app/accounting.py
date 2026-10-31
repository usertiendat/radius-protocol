from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text

router = APIRouter(prefix="/api/v1", tags=["Accounting & Logs"])

# 1. Danh sách tất cả các phiên truy cập
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

# 2. Chi tiết 1 phiên truy cập cụ thể theo ID
@router.get("/accounting/sessions/{id}")
def get_accounting_session_by_id(id: int, db: Session = Depends()):
    query = text("""
        SELECT * FROM radacct WHERE radacctid = :id
    """)
    result = db.execute(query, {"id": id}).mappings().first()
    if not result:
        raise HTTPException(status_code=404, detail="Session not found")
    return dict(result)

# 3. Thống kê dung lượng & tổng thời lượng mạng
@router.get("/accounting/statistics")
def get_accounting_statistics(db: Session = Depends()):
    query = text("""
        SELECT 
            SUM(acctsessiontime) as total_duration,
            SUM(acctinputoctets) as total_download_bytes,
            SUM(acctoutputoctets) as total_upload_bytes
        FROM radacct
    """)
    result = db.execute(query).mappings().first()
    return dict(result)

# 4. Lịch sử xác thực từ radpostauth
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

# 5. Thống kê tổng quan cho Dashboard
@router.get("/dashboard/summary")
def get_dashboard_summary(db: Session = Depends()):
    total_sessions = db.execute(text("SELECT COUNT(*) FROM radacct")).scalar() or 0
    active_sessions = db.execute(text("SELECT COUNT(*) FROM radacct WHERE acctstoptime IS NULL")).scalar() or 0
    total_users = db.execute(text("SELECT COUNT(DISTINCT username) FROM radcheck")).scalar() or 0
    
    return {
        "total_sessions": total_sessions,
        "active_sessions": active_sessions,
        "total_users": total_users
    }