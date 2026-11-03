"""
Bộ kiểm thử đơn vị cho Global Exception Handling & HTTP Error Mapping (Phase 0B - Step 3.3.3).
Kiểm thử độc lập, không kết nối MariaDB thật hoặc socket mạng ngoài.
"""

import json
import sys
from pathlib import Path

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import (
    http_exception_handler as default_http_exception_handler,
    request_validation_exception_handler as default_validation_handler,
)
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import (
    BaseBusinessException,
    BusinessValidationError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceUnavailableError,
    UnauthorizedError,
    ValidationError,
)
from app.core.exception_handlers import (
    business_exception_handler,
    register_exception_handlers,
    transaction_already_active_handler,
    unhandled_exception_handler,
)
from app.main import app
from app.services.transaction import TransactionAlreadyActiveError


def make_mock_request(path: str = "/api/v1/resource", method: str = "GET") -> Request:
    """Tạo mock Request an toàn cho kiểm thử Exception Handlers."""
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode("ascii"),
        "headers": [],
        "query_string": b"",
    }
    return Request(scope)


def run_coro_sync(coro):
    """
    Thực thi coroutine đồng bộ không dùng socket/loop để an toàn trong môi trường sandbox.
    Áp dụng cho các async exception handler của FastAPI vốn chỉ tạo Response mà không I/O.
    """
    try:
        coro.send(None)
    except StopIteration as e:
        return e.value
    raise RuntimeError("Coroutine không thể hoàn tất đồng bộ")


# -----------------------------------------------------------------------------
# 1. KIỂM THỬ ÁNH XẠ STATUS CODE & ERROR CODE CHO BUSINESS EXCEPTIONS
# -----------------------------------------------------------------------------

def test_not_found_error_mapped_to_404():
    """Kiểm tra NotFoundError được ánh xạ chính xác thành HTTP 404 và mã lỗi RESOURCE_NOT_FOUND."""
    req = make_mock_request()
    exc = NotFoundError(message="Người dùng không tồn tại", code="USER_NOT_FOUND")
    resp = business_exception_handler(req, exc)

    assert resp.status_code == 404
    data = json.loads(resp.body.decode("utf-8"))
    assert data == {
        "error": {
            "code": "USER_NOT_FOUND",
            "message": "Người dùng không tồn tại",
        }
    }


def test_conflict_error_mapped_to_409():
    """Kiểm tra ConflictError được ánh xạ chính xác thành HTTP 409 và mã lỗi RESOURCE_CONFLICT."""
    req = make_mock_request()
    exc = ConflictError("Tên người dùng đã tồn tại trong hệ thống")
    resp = business_exception_handler(req, exc)

    assert resp.status_code == 409
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "RESOURCE_CONFLICT"
    assert data["error"]["message"] == "Tên người dùng đã tồn tại trong hệ thống"


def test_unauthorized_error_mapped_to_401():
    """Kiểm tra UnauthorizedError được ánh xạ chính xác thành HTTP 401."""
    req = make_mock_request()
    exc = UnauthorizedError("Mã token đã hết hạn hoặc không hợp lệ")
    resp = business_exception_handler(req, exc)

    assert resp.status_code == 401
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "UNAUTHORIZED"
    assert data["error"]["message"] == "Mã token đã hết hạn hoặc không hợp lệ"


def test_forbidden_error_mapped_to_403():
    """Kiểm tra ForbiddenError được ánh xạ chính xác thành HTTP 403."""
    req = make_mock_request()
    exc = ForbiddenError("Tài khoản không có quyền truy cập module này")
    resp = business_exception_handler(req, exc)

    assert resp.status_code == 403
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "FORBIDDEN"
    assert data["error"]["message"] == "Tài khoản không có quyền truy cập module này"


def test_service_unavailable_error_mapped_to_503():
    """Kiểm tra ServiceUnavailableError được ánh xạ chính xác thành HTTP 503."""
    req = make_mock_request()
    exc = ServiceUnavailableError("Máy chủ FreeRADIUS hiện không phản hồi")
    resp = business_exception_handler(req, exc)

    assert resp.status_code == 503
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "SERVICE_UNAVAILABLE"
    assert data["error"]["message"] == "Máy chủ FreeRADIUS hiện không phản hồi"


def test_validation_error_mapped_to_422():
    """Kiểm tra ValidationError được ánh xạ chính xác thành HTTP 422."""
    req = make_mock_request()
    exc = ValidationError("Độ dài mật khẩu phải tối thiểu 8 ký tự")
    resp = business_exception_handler(req, exc)

    assert resp.status_code == 422
    data = json.loads(resp.body.decode("utf-8"))
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert data["error"]["message"] == "Độ dài mật khẩu phải tối thiểu 8 ký tự"


# -----------------------------------------------------------------------------
# 2. KIỂM THỬ CẤU TRÚC JSON RESPONSE THỐNG NHẤT
# -----------------------------------------------------------------------------

def test_json_response_structure_is_standardized():
    """Xác nhận cấu trúc JSON response luôn tuân thủ chuẩn {'error': {'code': ..., 'message': ...}}."""
    req = make_mock_request()

    for exc in [
        NotFoundError(),
        ConflictError(),
        UnauthorizedError(),
        ForbiddenError(),
        ServiceUnavailableError(),
        ValidationError(),
        BusinessValidationError(),
    ]:
        resp = business_exception_handler(req, exc)
        data = json.loads(resp.body.decode("utf-8"))

        # 1. Phải có khóa gốc "error"
        assert "error" in data
        assert isinstance(data["error"], dict)

        # 2. Phải chứa chính xác 2 khóa "code" và "message"
        assert set(data["error"].keys()) == {"code", "message"}
        assert isinstance(data["error"]["code"], str)
        assert isinstance(data["error"]["message"], str)

        # 3. Không có khóa nhạy cảm
        assert "stack_trace" not in data
        assert "traceback" not in data
        assert "detail" not in data


def test_error_codes_accurate_and_frontend_friendly():
    """Kiểm tra toàn bộ mã lỗi định danh là chuỗi in hoa rõ ràng, thân thiện với Frontend."""
    req = make_mock_request()

    expected_codes = {
        NotFoundError: "RESOURCE_NOT_FOUND",
        ConflictError: "RESOURCE_CONFLICT",
        UnauthorizedError: "UNAUTHORIZED",
        ForbiddenError: "FORBIDDEN",
        ServiceUnavailableError: "SERVICE_UNAVAILABLE",
        ValidationError: "VALIDATION_ERROR",
    }

    for exc_cls, expected_code in expected_codes.items():
        resp = business_exception_handler(req, exc_cls())
        data = json.loads(resp.body.decode("utf-8"))
        assert data["error"]["code"] == expected_code


# -----------------------------------------------------------------------------
# 3. KIỂM THỬ BẢO TỒN HTTPEXCEPTION VÀ REQUESTVALIDATIONERROR MẶC ĐỊNH
# -----------------------------------------------------------------------------

def test_http_exception_remains_active_and_untouched():
    """Kiểm tra unhandled_exception_handler không chặn HTTPException, bảo toàn cơ chế mặc định của FastAPI."""
    req = make_mock_request()
    http_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Tên đăng nhập hoặc mật khẩu không hợp lệ.",
    )

    # unhandled_exception_handler phải re-raise HTTPException để FastAPI xử lý theo flow chuẩn
    with pytest.raises(HTTPException) as exc_info:
        unhandled_exception_handler(req, http_exc)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Tên đăng nhập hoặc mật khẩu không hợp lệ."

    # Handler mặc định của FastAPI xử lý đúng định dạng chuẩn {"detail": "..."}
    default_resp = run_coro_sync(default_http_exception_handler(req, http_exc))
    assert default_resp.status_code == 401
    data = json.loads(default_resp.body.decode("utf-8"))
    assert data == {"detail": "Tên đăng nhập hoặc mật khẩu không hợp lệ."}


def test_request_validation_error_remains_active():
    """Kiểm tra RequestValidationError của FastAPI không bị biến thành lỗi 500."""
    req = make_mock_request()
    validation_exc = RequestValidationError(
        errors=[{"loc": ("body", "username"), "msg": "field required", "type": "value_error.missing"}]
    )

    # unhandled_exception_handler phải re-raise RequestValidationError
    with pytest.raises(RequestValidationError):
        unhandled_exception_handler(req, validation_exc)

    # Handler mặc định của FastAPI xử lý đúng HTTP 422
    default_resp = run_coro_sync(default_validation_handler(req, validation_exc))
    assert default_resp.status_code == 422
    data = json.loads(default_resp.body.decode("utf-8"))
    assert "detail" in data
    assert len(data["detail"]) == 1
    assert data["detail"][0]["loc"] == ["body", "username"]


# -----------------------------------------------------------------------------
# 4. KIỂM THỬ BẢO MẬT & NGOẠI LỆ GIAO DỊCH / NGOẠI LỆ KHÔNG XÁC ĐỊNH
# -----------------------------------------------------------------------------

def test_transaction_already_active_error_returns_500_without_leaking_internals():
    """
    Kiểm tra TransactionAlreadyActiveError được xử lý an toàn:
    - Trả về HTTP 500
    - Không làm rò rỉ thông điệp kỹ thuật nội bộ ra ngoài client
    """
    req = make_mock_request()
    internal_msg = "Session đã có transaction đang hoạt động. Chi tiết ranh giới nội bộ."
    exc = TransactionAlreadyActiveError(internal_msg)

    resp = transaction_already_active_handler(req, exc)

    assert resp.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    data = json.loads(resp.body.decode("utf-8"))

    # Cấu trúc response an toàn
    assert data == {
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "Đã xảy ra sự cố nội bộ trong quá trình xử lý giao dịch.",
        }
    }

    # Tuyệt đối không chứa thông điệp kỹ thuật nội bộ
    body_text = resp.body.decode("utf-8")
    assert "Session đã có transaction" not in body_text
    assert internal_msg not in body_text


def test_unhandled_exception_does_not_leak_stack_trace_or_credentials():
    """
    Kiểm tra ngoại lệ bất ngờ (Unhandled Exception) không để lộ database credentials,
    connection URL, hoặc stack trace ra ngoài client.
    """
    req = make_mock_request()
    sensitive_msg = "Critical crash: mysql+pymysql://root:SecretP@ssword123!@10.0.0.1:3306/radius_db failed"
    exc = RuntimeError(sensitive_msg)

    resp = unhandled_exception_handler(req, exc)

    assert resp.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    data = json.loads(resp.body.decode("utf-8"))

    # Trả về thông báo chung, an toàn
    assert data == {
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "Đã xảy ra lỗi máy chủ nội bộ. Vui lòng thử lại sau.",
        }
    }

    # Xác minh không rò rỉ bất kỳ thông tin nhạy cảm nào
    body_text = resp.body.decode("utf-8")
    assert "SecretP@ssword123!" not in body_text
    assert "mysql+pymysql" not in body_text
    assert "10.0.0.1" not in body_text
    assert "Critical crash" not in body_text
    assert "Traceback" not in body_text


# -----------------------------------------------------------------------------
# 5. KIỂM THỬ TÍCH HỢP TRÊN FASTAPI APPLICATION INSTANCE
# -----------------------------------------------------------------------------

def test_exception_handlers_registered_in_main_application():
    """Kiểm tra toàn bộ Exception Handlers đã được đăng ký đầy đủ trên app trong app/main.py."""
    handlers = app.exception_handlers

    # 1. BaseBusinessException và các lớp con
    assert BaseBusinessException in handlers
    assert NotFoundError in handlers
    assert ConflictError in handlers
    assert UnauthorizedError in handlers
    assert ForbiddenError in handlers
    assert ServiceUnavailableError in handlers
    assert ValidationError in handlers

    # 2. Transaction safety handler
    assert TransactionAlreadyActiveError in handlers

    # 3. Unhandled general exception
    assert Exception in handlers

    # 4. FastAPI default handlers được bảo toàn
    assert StarletteHTTPException in handlers
    assert RequestValidationError in handlers


def _get_all_app_routes(application):
    """Trích xuất danh sách tất cả (path, methods) của các route trong FastAPI application."""
    routes = []
    for r in application.routes:
        if hasattr(r, "path"):
            routes.append((r.path, getattr(r, "methods", set())))
        elif hasattr(r, "original_router"):
            for sub_r in r.original_router.routes:
                routes.append((sub_r.path, getattr(sub_r, "methods", set())))
    return routes


def test_existing_application_endpoints_and_docs_preserved():
    """Kiểm tra việc tích hợp exception handlers không làm ảnh hưởng đến các router và docs hiện có."""
    routes = _get_all_app_routes(app)
    route_paths = [path for path, methods in routes]

    # Endpoints hiện có vẫn tồn tại đầy đủ
    assert "/health" in route_paths
    assert "/health/database" in route_paths
    assert "/auth/login" in route_paths

    # Swagger và OpenAPI docs vẫn tồn tại đầy đủ
    assert "/docs" in route_paths
    assert "/openapi.json" in route_paths
