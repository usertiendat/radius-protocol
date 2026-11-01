"""Bộ kiểm thử Unit và Mock Tests cho FastAPI RADIUS Authentication API.

Bộ test này hoàn toàn ĐỘC LẬP:
- Không yêu cầu FreeRADIUS server đang chạy.
- Không phụ thuộc môi trường Ubuntu/WSL hay địa chỉ IP mạng.
- Không phụ thuộc vào nội dung file .env thật.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Đảm bảo đường dẫn backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi.testclient import TestClient

from app.main import app
from app.radius_auth import (
    RadiusAuthenticationFailed,
    RadiusConfigError,
    RadiusConnectionError,
    close_client,
)

client = TestClient(app)


def test_health_check():
    """Kiểm tra GET /health giữ nguyên cấu trúc và trả về HTTP 200."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "radius-backend",
    }
    print("[PASS] test_health_check")


def test_login_mock_success_200():
    """Kiểm tra POST /auth/login khi FreeRADIUS trả về Access-Accept (HTTP 200)."""
    with patch("app.main.authenticate_radius") as mock_auth:
        mock_auth.return_value = None  # Thành công
        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "TestPass123"},
        )
        assert response.status_code == 200
        assert response.json() == {
            "success": True,
            "message": "Xác thực thành công.",
        }
        mock_auth.assert_called_once_with("testuser", "TestPass123")
    print("[PASS] test_login_mock_success_200")


def test_login_mock_reject_401():
    """Kiểm tra POST /auth/login khi FreeRADIUS trả về Access-Reject (HTTP 401)."""
    with patch("app.main.authenticate_radius") as mock_auth:
        mock_auth.side_effect = RadiusAuthenticationFailed(
            "Tên đăng nhập hoặc mật khẩu không hợp lệ."
        )
        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "WrongPassword"},
        )
        assert response.status_code == 401
        assert response.json() == {
            "detail": "Tên đăng nhập hoặc mật khẩu không hợp lệ."
        }
    print("[PASS] test_login_mock_reject_401")


def test_login_mock_timeout_503():
    """Kiểm tra POST /auth/login khi xảy ra Timeout (HTTP 503, không lộ traceback)."""
    with patch("app.main.authenticate_radius") as mock_auth:
        mock_auth.side_effect = RadiusConnectionError("Timeout chờ FreeRADIUS")
        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "TestPass123"},
        )
        assert response.status_code == 503
        assert response.json() == {
            "detail": "Dịch vụ xác thực hiện không khả dụng."
        }
    print("[PASS] test_login_mock_timeout_503")


def test_login_mock_socket_error_503():
    """Kiểm tra POST /auth/login khi lỗi mạng/socket (HTTP 503)."""
    with patch("app.main.authenticate_radius") as mock_auth:
        mock_auth.side_effect = RadiusConnectionError("Lỗi kết nối socket")
        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "TestPass123"},
        )
        assert response.status_code == 503
        assert response.json() == {
            "detail": "Dịch vụ xác thực hiện không khả dụng."
        }
    print("[PASS] test_login_mock_socket_error_503")


def test_login_mock_config_error_503():
    """Kiểm tra POST /auth/login khi thiếu biến môi trường hoặc file từ điển (HTTP 503)."""
    with patch("app.main.authenticate_radius") as mock_auth:
        mock_auth.side_effect = RadiusConfigError("Thiếu RADIUS_SERVER")
        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "TestPass123"},
        )
        assert response.status_code == 503
        assert response.json() == {
            "detail": "Dịch vụ xác thực hiện không khả dụng."
        }
    print("[PASS] test_login_mock_config_error_503")


def test_login_validation_empty_username_422():
    """Kiểm tra khi username chỉ chứa khoảng trắng (HTTP 422)."""
    response = client.post(
        "/auth/login",
        json={"username": "   ", "password": "ValidPassword123"},
    )
    assert response.status_code == 422
    print("[PASS] test_login_validation_empty_username_422")


def test_login_validation_empty_password_422():
    """Kiểm tra khi password chỉ chứa khoảng trắng (HTTP 422)."""
    response = client.post(
        "/auth/login",
        json={"username": "validuser", "password": "   "},
    )
    assert response.status_code == 422
    print("[PASS] test_login_validation_empty_password_422")


def test_login_validation_missing_fields_422():
    """Kiểm tra khi thiếu trường username hoặc password (HTTP 422)."""
    response1 = client.post(
        "/auth/login",
        json={"password": "ValidPassword123"},
    )
    assert response1.status_code == 422

    response2 = client.post(
        "/auth/login",
        json={"username": "validuser"},
    )
    assert response2.status_code == 422
    print("[PASS] test_login_validation_missing_fields_422")


def test_login_validation_preserves_password_spaces():
    """Kiểm tra mật khẩu có khoảng trắng bên trong được giữ nguyên vẹn."""
    with patch("app.main.authenticate_radius") as mock_auth:
        mock_auth.return_value = None
        raw_password = "  Secret Pass With Spaces  "
        response = client.post(
            "/auth/login",
            json={"username": "  testuser  ", "password": raw_password},
        )
        assert response.status_code == 200
        # Username được strip sạch, password giữ nguyên vẹn từng khoảng trắng
        mock_auth.assert_called_once_with("testuser", raw_password)
    print("[PASS] test_login_validation_preserves_password_spaces")


def test_close_client_idempotent():
    """Kiểm tra hàm close_client dọn dẹp socket idempotent và không lỗi."""
    mock_pyrad_client = MagicMock()
    # Lần 1: gọi bình thường
    close_client(mock_pyrad_client)
    mock_pyrad_client._close_socket.assert_called_once()

    # Lần 2: gọi lại không phát sinh lỗi
    close_client(mock_pyrad_client)

    # Thử với đối tượng rỗng không có _close_socket
    dummy = object()
    close_client(dummy)  # Không được raise
    print("[PASS] test_close_client_idempotent")


def run_all_unit_tests():
    print("=" * 60)
    print("CHẠY BỘ KIỂM THỬ ĐỘC LẬP: UNIT / MOCK TESTS")
    print("=" * 60)
    test_health_check()
    test_login_mock_success_200()
    test_login_mock_reject_401()
    test_login_mock_timeout_503()
    test_login_mock_socket_error_503()
    test_login_mock_config_error_503()
    test_login_validation_empty_username_422()
    test_login_validation_empty_password_422()
    test_login_validation_missing_fields_422()
    test_login_validation_preserves_password_spaces()
    test_close_client_idempotent()
    print("=" * 60)
    print("TẤT CẢ 11 UNIT / MOCK TESTS ĐÃ VƯỢT QUA THÀNH CÔNG!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_unit_tests()
