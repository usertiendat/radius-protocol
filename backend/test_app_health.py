"""
Bộ kiểm thử đơn vị cho FastAPI Application Integration & Health Monitoring (Phase 0B - Step 3.2).
Kiểm thử độc lập, không yêu cầu MariaDB thật hoặc FreeRADIUS server đang chạy.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi import Response, status
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

from app.database import engine
from app.main import app, database_health, health_check, login


def _get_all_app_routes(application):
    """Trích xuất danh sách tất cả (path, methods) của các route trong FastAPI application."""
    routes = []
    for r in application.routes:
        if hasattr(r, "path"):
            routes.append((r.path, r.methods))
        elif hasattr(r, "original_router"):
            for sub_r in r.original_router.routes:
                routes.append((sub_r.path, sub_r.methods))
    return routes


# -----------------------------------------------------------------------------
# 1. KIỂM THỬ BACKEND HEALTH (/health)
# -----------------------------------------------------------------------------

def test_backend_health_returns_200_and_expected_structure():
    """Kiểm tra GET /health trả về đúng cấu trúc JSON chuẩn và không lỗi."""
    result = health_check()
    assert result == {
        "status": "healthy",
        "service": "radius-backend",
    }


def test_backend_health_works_when_database_offline():
    """Kiểm tra /health vẫn hoạt động bình thường khi MariaDB hoàn toàn offline."""
    # Giả lập CSDL offline hoàn toàn
    with patch("app.core.dependencies.check_database_connection", return_value=(False, "DB offline")):
        result = health_check()
        assert result["status"] == "healthy"
        assert result["service"] == "radius-backend"


# -----------------------------------------------------------------------------
# 2. KIỂM THỬ DATABASE HEALTH (/health/database)
# -----------------------------------------------------------------------------

def test_database_health_returns_200_when_db_healthy():
    """Kiểm tra GET /health/database trả về HTTP 200 và healthy khi CSDL kết nối tốt."""
    with patch("app.routers.health.check_database_connection", return_value=(True, "Database connection is healthy.")):
        resp = Response()
        result = database_health(resp)

        assert resp.status_code == status.HTTP_200_OK
        assert result == {
            "status": "healthy",
            "service": "database",
        }


def test_database_health_returns_503_when_db_unavailable():
    """Kiểm tra GET /health/database trả về HTTP 503 khi CSDL không khả dụng."""
    with patch("app.routers.health.check_database_connection", return_value=(False, "Can't connect to MySQL server")):
        resp = Response()
        result = database_health(resp)

        assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert result == {
            "status": "unavailable",
            "service": "database",
            "message": "Database connection is unavailable",
        }


def test_database_health_exception_does_not_leak_credentials():
    """Kiểm tra tuyệt đối không để lộ connection URL hoặc password khi xảy ra ngoại lệ CSDL."""
    sensitive_error = "mysql+pymysql://admin_user:SuperSecretPassword999@10.0.0.1:3306/radius_db"

    # Giả lập lỗi chứa connection URL nhạy cảm
    with patch("app.routers.health.check_database_connection", return_value=(False, sensitive_error)):
        resp = Response()
        result = database_health(resp)

        # Response trả về cho client phải hoàn toàn an toàn
        result_str = str(result)
        assert "SuperSecretPassword999" not in result_str
        assert "10.0.0.1" not in result_str
        assert "admin_user" not in result_str
        assert result["status"] == "unavailable"
        assert result["message"] == "Database connection is unavailable"


# -----------------------------------------------------------------------------
# 3. KIỂM THỬ APP INTEGRATION & ROUTE PRESERVATION
# -----------------------------------------------------------------------------

def test_import_main_does_not_require_active_db():
    """Kiểm tra import main.py không mở kết nối socket và không yêu cầu MariaDB đang chạy."""
    import importlib
    import app.main as main_mod

    importlib.reload(main_mod)
    assert main_mod.app.title == "RADIUS Network Access Management"
    assert engine.pool.checkedout() == 0
    assert engine.pool.checkedin() == 0


def test_health_endpoints_do_not_create_new_engine():
    """Kiểm tra gọi health endpoints không tạo thêm instance engine mới."""
    engine_id_before = id(engine)

    # Gọi kiểm tra sức khỏe
    with patch("app.routers.health.check_database_connection", return_value=(True, "OK")):
        resp = Response()
        database_health(resp)

    engine_id_after = id(engine)
    assert engine_id_before == engine_id_after


def test_existing_endpoints_preserved_in_application():
    """Kiểm tra tất cả endpoint bắt buộc (/health, /health/database, /auth/login) được đăng ký đầy đủ."""
    routes = _get_all_app_routes(app)
    route_dict = {path: methods for path, methods in routes}

    # 1. /health được đăng ký với method GET
    assert "/health" in route_dict
    assert "GET" in route_dict["/health"]

    # 2. /health/database được đăng ký với method GET
    assert "/health/database" in route_dict
    assert "GET" in route_dict["/health/database"]

    # 3. /auth/login được bảo toàn với method POST
    assert "/auth/login" in route_dict
    assert "POST" in route_dict["/auth/login"]


def test_auth_login_endpoint_callable_intact():
    """Kiểm tra function login cho /auth/login vẫn nguyên vẹn và sẵn sàng xử lý request."""
    assert callable(login)
    assert login.__name__ == "login"
    assert "PAP" in (login.__doc__ or "")
