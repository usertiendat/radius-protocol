from fastapi import FastAPI
from app.accounting import router as accounting_router

app = FastAPI(
    title="RADIUS Network Access Management",
    description="API quản lý xác thực và giám sát truy cập mạng",
    version="0.1.0",
)

# Đăng ký các API endpoint của module Accounting & Logs
app.include_router(accounting_router)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "radius-backend",
    }