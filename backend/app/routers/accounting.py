from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import date

# 1. Thêm import get_db đúng chuẩn theo yêu cầu
try:
    from app.core.dependencies import get_db
except ImportError:
    from app.database import get_db

router = APIRouter(prefix="/api/v1", tags=["Accounting & Logs"])

# 1. GET /api/v1/accounting/sessions (Lịch sử các phiên kết nối, sắp xếp giảm dần, hỗ trợ phân trang)
@router.get("/accounting/sessions")
def get_accounting_sessions(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
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

# 2. GET /api/v1/accounting/sessions/{id} (Chi tiết 1 phiên kết nối)
@router.get("/accounting/sessions/{id}")
def get_accounting_session_by_id(id: int, db: Session = Depends(get_db)):
    query = text("""
        SELECT * FROM radacct WHERE radacctid = :id
    """)
    result = db.execute(query, {"id": id}).mappings().first()
    if not result:
        raise HTTPException(status_code=404, detail="Session not found")
    return dict(result)

# 3. GET /api/v1/accounting/statistics (Thống kê active sessions, tổng dung lượng và thời lượng)
@router.get("/accounting/statistics")
def get_accounting_statistics(db: Session = Depends(get_db)):
    query = text("""
        SELECT 
            COUNT(CASE WHEN acctstoptime IS NULL THEN 1 END) as active_sessions,
            COALESCE(SUM(acctsessiontime), 0) as total_duration,
            COALESCE(SUM(acctinputoctets), 0) as total_download_bytes,
            COALESCE(SUM(acctoutputoctets), 0) as total_upload_bytes
        FROM radacct
    """)
    result = db.execute(query).mappings().first()
    return dict(result)

# 4. GET /api/v1/logs/authentication (Đọc lịch sử xác thực từ radpostauth, an toàn không chọn cột pass)
@router.get("/logs/authentication")
@router.get("/monitoring/logs")
def get_auth_logs(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    query = text("""
        SELECT id, username, reply, authdate 
        FROM radpostauth 
        ORDER BY authdate DESC 
        LIMIT :limit OFFSET :skip
    """)
    result = db.execute(query, {"limit": limit, "skip": skip}).mappings().all()
    return list(result)

# 5. GET /api/v1/dashboard/summary (Tổng số User, số thiết bị NAS, số phiên active, và lượt login hôm nay)
@router.get("/dashboard/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    today_str = date.today().isoformat()
    
    total_users = db.execute(text("SELECT COUNT(DISTINCT username) FROM radcheck")).scalar() or 0
    total_nas = db.execute(text("SELECT COUNT(*) FROM nas")).scalar() or 0
    active_sessions = db.execute(text("SELECT COUNT(*) FROM radacct WHERE acctstoptime IS NULL")).scalar() or 0
    
    login_success_today = db.execute(text("""
        SELECT COUNT(*) FROM radpostauth 
        WHERE reply = 'Access-Accept' AND DATE(authdate) = :today
    """), {"today": today_str}).scalar() or 0
    
    login_failed_today = db.execute(text("""
        SELECT COUNT(*) FROM radpostauth 
        WHERE reply = 'Access-Reject' AND DATE(authdate) = :today
    """), {"today": today_str}).scalar() or 0
    
    return {
        "total_users": total_users,
        "total_nas": total_nas,
        "active_sessions": active_sessions,
        "login_success_today": login_success_today,
        "login_failed_today": login_failed_today
    }