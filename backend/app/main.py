
from fastapi import FastAPI

app = FastAPI(
    title="RADIUS Network Access Management",
    description="API quản lý xác thực và giám sát truy cập mạng",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "radius-backend",
    }
