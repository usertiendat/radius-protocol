"""Bộ kiểm thử Tích hợp (Integration Tests) với FreeRADIUS thật và Backend API.

Yêu cầu trước khi chạy script này:
1. Máy chủ FreeRADIUS 3.2.8 trên Ubuntu/WSL đã được khởi động (sudo freeradius -X).
2. Backend API Uvicorn đang chạy trên một TERMINAL RIÊNG BIỆT:
   $env:PYTHONUTF8=1; .venv\\Scripts\\python.exe -m uvicorn app.main:app --app-dir backend --reload
"""

import sys
from pathlib import Path

# Đảm bảo đường dẫn backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import httpx

API_BASE_URL = "http://127.0.0.1:8000"


def check_backend_readiness() -> bool:
    """Kiểm tra xem backend Uvicorn đã được khởi động hay chưa."""
    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(f"{API_BASE_URL}/health")
            if resp.status_code == 200 and resp.json().get("status") == "healthy":
                return True
    except (httpx.ConnectError, httpx.TimeoutException, OSError):
        pass
    return False


def run_integration_tests():
    print("=" * 65)
    print("BẮT ĐẦU KIỂM THỬ TÍCH HỢP (INTEGRATION TESTS) VỚI FREERADIUS THẬT")
    print("=" * 65)

    # 1. Kiểm tra tính sẵn sàng của backend
    print(f"[*] Kiểm tra kết nối tới Backend API tại {API_BASE_URL}...")
    if not check_backend_readiness():
        print()
        print("!" * 65)
        print("THÔNG BÁO: Backend API chưa hoạt động tại http://127.0.0.1:8000.")
        print("Vui lòng mở một Terminal PowerShell RIÊNG BIỆT và khởi động backend:")
        print()
        print("  $env:PYTHONUTF8=1; .venv\\Scripts\\python.exe -m uvicorn app.main:app --app-dir backend --reload")
        print()
        print("Sau khi terminal đó hiển thị 'Application startup complete', hãy")
        print("chạy lại lệnh test này tại terminal hiện tại.")
        print()
        print("LƯU Ý: Đây KHÔNG PHẢI là lỗi xác thực FreeRADIUS mà là do")
        print("server FastAPI Uvicorn chưa được bật.")
        print("!" * 65)
        sys.exit(1)

    print("[OK] Backend API đang hoạt động và sẵn sàng nhận request.\n")

    with httpx.Client(base_url=API_BASE_URL, timeout=5.0) as client:
        # Ca 1: Đúng tài khoản và đúng mật khẩu
        print("[*] Ca 1: Gửi 'testuser' với mật khẩu đúng 'TestPass123'...")
        resp1 = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "TestPass123"},
        )
        assert resp1.status_code == 200, f"Mong đợi 200, nhận {resp1.status_code}: {resp1.text}"
        data1 = resp1.json()
        assert data1.get("success") is True
        print(f"    -> [PASS] HTTP {resp1.status_code}: {data1}\n")

        # Ca 2: Đúng tài khoản nhưng sai mật khẩu
        print("[*] Ca 2: Gửi 'testuser' với mật khẩu sai 'WrongPassword123'...")
        resp2 = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "WrongPassword123"},
        )
        assert resp2.status_code == 401, f"Mong đợi 401, nhận {resp2.status_code}: {resp2.text}"
        data2 = resp2.json()
        assert data2.get("detail") == "Tên đăng nhập hoặc mật khẩu không hợp lệ."
        print(f"    -> [PASS] HTTP {resp2.status_code}: {data2}\n")

        # Ca 3: Tài khoản không tồn tại
        print("[*] Ca 3: Gửi tài khoản không tồn tại 'nonexistent_user'...")
        resp3 = client.post(
            "/auth/login",
            json={"username": "nonexistent_user", "password": "AnyPassword123"},
        )
        assert resp3.status_code == 401, f"Mong đợi 401, nhận {resp3.status_code}: {resp3.text}"
        data3 = resp3.json()
        assert data3.get("detail") == "Tên đăng nhập hoặc mật khẩu không hợp lệ."
        print(f"    -> [PASS] HTTP {resp3.status_code}: {data3}\n")

    print("=" * 65)
    print("XÁC NHẬN: TẤT CẢ CÁC CA KIỂM THỬ TÍCH HỢP ĐỀU THÀNH CÔNG VỚI FREERADIUS THẬT!")
    print("=" * 65)


if __name__ == "__main__":
    run_integration_tests()
