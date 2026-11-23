"""
Bộ kiểm thử đơn vị cho Admin Token Service (Phase 0B - Step 3.4.2).
Kiểm thử độc lập với test secret key, không phụ thuộc CSDL hay môi trường ngoài.
Bao gồm đầy đủ 18 test cases bắt buộc theo đặc tả Phase 0B Step 3.4.2.
"""

import ast
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Any, Dict
from unittest.mock import patch

# Đảm bảo thư mục backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import jwt
import pytest

from app.core.config import settings
from app.core.exceptions import ServiceUnavailableError, UnauthorizedError, ValidationError
from app.models.application import AppAdmin
from app.services import (
    AdminAuthResult,
    AdminTokenClaims,
    AdminTokenService,
)

# Secret key giả lập dùng riêng cho unit testing (không dùng bí mật thật)
TEST_SECRET_KEY = "test-jwt-secret-key-32-chars-long-for-safe-unit-testing"
ANOTHER_SECRET_KEY = "another-wrong-secret-key-for-testing-signatures-32c"


@pytest.fixture
def token_service() -> AdminTokenService:
    """Khởi tạo AdminTokenService độc lập với secret key an toàn cho test."""
    return AdminTokenService(secret_key=TEST_SECRET_KEY)


@pytest.fixture
def sample_admin() -> AppAdmin:
    """Tạo đối tượng AppAdmin mẫu đầy đủ thông tin."""
    return AppAdmin(
        id=42,
        username="super_admin",
        password_hash="pbkdf2_sha256$310000$test$fakehash",
        email="admin@enterprise.local",
        role="superadmin",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )


# =============================================================================
# 18 BỘ KIỂM THỬ BẮT BUỘC THEO ĐẶC TẢ STEP 3.4.2
# =============================================================================

def test_01_issue_access_token_success(token_service: AdminTokenService, sample_admin: AppAdmin):
    """1. Phát hành Access Token thành công từ đối tượng Admin hợp lệ."""
    token = token_service.create_access_token(sample_admin)

    assert isinstance(token, str)
    assert len(token.strip()) > 30
    assert len(token.split(".")) == 3  # Header.Payload.Signature


def test_02_token_algorithm_is_hs256(token_service: AdminTokenService, sample_admin: AppAdmin):
    """2. Token bắt buộc phải sử dụng thuật toán HS256."""
    token = token_service.create_access_token(sample_admin)
    unverified_header = jwt.get_unverified_header(token)

    assert unverified_header.get("alg") == "HS256"
    assert unverified_header.get("typ") == "JWT"


def test_03_token_expiration_is_30_minutes(token_service: AdminTokenService, sample_admin: AppAdmin):
    """3. Token có thời hạn chuẩn 30 phút (exp - iat = 1800 giây)."""
    token = token_service.create_access_token(sample_admin)
    unverified_payload = jwt.decode(token, options={"verify_signature": False})

    iat = unverified_payload["iat"]
    exp = unverified_payload["exp"]
    diff_seconds = exp - iat

    expected_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60  # 30 * 60 = 1800
    assert diff_seconds == expected_seconds
    assert diff_seconds == 1800


def test_04_token_contains_exact_sub(token_service: AdminTokenService, sample_admin: AppAdmin):
    """4. Token chứa đúng claim 'sub' (ID định danh dạng chuỗi)."""
    token = token_service.create_access_token(sample_admin)
    unverified_payload = jwt.decode(token, options={"verify_signature": False})

    assert unverified_payload.get("sub") == str(sample_admin.id)
    assert unverified_payload.get("sub") == "42"


def test_05_token_contains_exact_role(token_service: AdminTokenService, sample_admin: AppAdmin):
    """5. Token chứa đúng claim 'role' của Admin."""
    token = token_service.create_access_token(sample_admin)
    unverified_payload = jwt.decode(token, options={"verify_signature": False})

    assert unverified_payload.get("role") == sample_admin.role
    assert unverified_payload.get("role") == "superadmin"


def test_06_token_contains_iat_and_exp(token_service: AdminTokenService, sample_admin: AppAdmin):
    """6. Token chứa đầy đủ 'iat' và 'exp' kiểu số nguyên hợp lệ."""
    token = token_service.create_access_token(sample_admin)
    unverified_payload = jwt.decode(token, options={"verify_signature": False})

    assert "iat" in unverified_payload
    assert "exp" in unverified_payload
    assert isinstance(unverified_payload["iat"], int)
    assert isinstance(unverified_payload["exp"], int)
    assert unverified_payload["exp"] > unverified_payload["iat"]


def test_07_token_does_not_contain_password(token_service: AdminTokenService):
    """7. Token tuyệt đối không chứa password dù đối tượng admin có thuộc tính password."""
    # Giả lập admin payload có chứa password rõ
    admin_with_pass = {
        "id": 101,
        "role": "it_admin",
        "password": "ClearTextPasswordShouldNeverBeInToken!",
    }
    token = token_service.create_access_token(admin_with_pass)
    unverified_payload = jwt.decode(token, options={"verify_signature": False})

    assert "password" not in unverified_payload
    assert "ClearTextPasswordShouldNeverBeInToken!" not in token


def test_08_token_does_not_contain_password_hash(token_service: AdminTokenService, sample_admin: AppAdmin):
    """8. Token tuyệt đối không chứa password_hash."""
    token = token_service.create_access_token(sample_admin)
    unverified_payload = jwt.decode(token, options={"verify_signature": False})

    assert "password_hash" not in unverified_payload
    assert sample_admin.password_hash not in token


def test_09_verify_valid_token_success(token_service: AdminTokenService, sample_admin: AppAdmin):
    """9. Xác minh token hợp lệ thành công và trả về AdminTokenClaims an toàn."""
    token = token_service.create_access_token(sample_admin)
    claims = token_service.verify_access_token(token)

    assert isinstance(claims, AdminTokenClaims)
    assert isinstance(claims, dict)  # Kế thừa dict
    assert claims.sub == "42"
    assert claims.role == "superadmin"
    assert claims.type == "access"
    assert claims["sub"] == "42"
    assert claims["role"] == "superadmin"
    assert claims["type"] == "access"
    assert isinstance(claims.exp, int)
    assert isinstance(claims.iat, int)


def test_10_reject_expired_token(token_service: AdminTokenService, sample_admin: AppAdmin):
    """10. Từ chối token đã hết hạn bằng UnauthorizedError (code: TOKEN_EXPIRED)."""
    # Tạo token đã hết hạn 5 phút trước
    expired_token = token_service.create_access_token(
        sample_admin,
        expires_delta=timedelta(minutes=-5),
    )

    with pytest.raises(UnauthorizedError) as exc_info:
        token_service.verify_access_token(expired_token)

    assert exc_info.value.code == "TOKEN_EXPIRED"
    assert "hết hạn" in exc_info.value.message.lower()


def test_11_reject_token_with_wrong_signature(token_service: AdminTokenService, sample_admin: AppAdmin):
    """11. Từ chối token bị ký bởi khóa bí mật khác bằng UnauthorizedError (code: TOKEN_INVALID)."""
    # Ký token bằng một khóa bí mật khác
    another_service = AdminTokenService(secret_key=ANOTHER_SECRET_KEY)
    tampered_token = another_service.create_access_token(sample_admin)

    with pytest.raises(UnauthorizedError) as exc_info:
        token_service.verify_access_token(tampered_token)

    assert exc_info.value.code == "TOKEN_INVALID"
    assert "không hợp lệ" in exc_info.value.message.lower()


def test_12_reject_malformed_or_garbage_token(token_service: AdminTokenService):
    """12. Từ chối token sai định dạng hoặc chuỗi rác bằng UnauthorizedError (code: TOKEN_INVALID)."""
    malformed_tokens = [
        "not-a-jwt-token",
        "header.payload",  # Thiếu signature
        "header.payload.signature.extra",  # Quá nhiều phần
        "",
        "   ",
    ]

    for bad_token in malformed_tokens:
        with pytest.raises(UnauthorizedError) as exc_info:
            token_service.verify_access_token(bad_token)
        assert exc_info.value.code == "TOKEN_INVALID"


def test_13_reject_token_missing_sub(token_service: AdminTokenService):
    """13. Từ chối token thiếu claim 'sub' bằng UnauthorizedError (code: TOKEN_INVALID)."""
    # Tạo token hợp lệ về chữ ký nhưng thiếu sub
    now = datetime.now(timezone.utc)
    payload_without_sub = {
        "role": "it_admin",
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    raw_token = jwt.encode(payload_without_sub, TEST_SECRET_KEY, algorithm="HS256")

    with pytest.raises(UnauthorizedError) as exc_info:
        token_service.verify_access_token(raw_token)

    assert exc_info.value.code == "TOKEN_INVALID"
    assert "sub" in exc_info.value.message.lower()


def test_14_reject_token_missing_role(token_service: AdminTokenService):
    """14. Từ chối token thiếu claim 'role' bằng UnauthorizedError (code: TOKEN_INVALID)."""
    # Tạo token hợp lệ về chữ ký nhưng thiếu role
    now = datetime.now(timezone.utc)
    payload_without_role = {
        "sub": "42",
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    raw_token = jwt.encode(payload_without_role, TEST_SECRET_KEY, algorithm="HS256")

    with pytest.raises(UnauthorizedError) as exc_info:
        token_service.verify_access_token(raw_token)

    assert exc_info.value.code == "TOKEN_INVALID"
    assert "role" in exc_info.value.message.lower()


def test_15_reject_token_with_forbidden_algorithm(token_service: AdminTokenService):
    """15. Từ chối token sử dụng thuật toán không được phép (alg=none hoặc thuật toán khác HS256)."""
    # A. Thử với thuật toán HS384 thay vì HS256
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "42",
        "role": "admin",
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    # Ký bằng HS384
    hs384_token = jwt.encode(payload, TEST_SECRET_KEY, algorithm="HS384")

    with pytest.raises(UnauthorizedError) as exc_info:
        token_service.verify_access_token(hs384_token)
    assert exc_info.value.code == "TOKEN_INVALID"

    # B. Thử với token giả mạo không có chữ ký (alg="none")
    header_none = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(b'{"sub":"42","role":"admin","type":"access"}').decode().rstrip("=")
    none_token = f"{header_none}.{payload_b64}."

    with pytest.raises(UnauthorizedError) as exc_info:
        token_service.verify_access_token(none_token)
    assert exc_info.value.code == "TOKEN_INVALID"


def test_16_reject_token_with_invalid_type(token_service: AdminTokenService):
    """16. Từ chối token có claim 'type' không hợp lệ (không phải 'access')."""
    now = datetime.now(timezone.utc)
    # Token có type = "refresh"
    payload_refresh = {
        "sub": "42",
        "role": "admin",
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    refresh_token = jwt.encode(payload_refresh, TEST_SECRET_KEY, algorithm="HS256")

    with pytest.raises(UnauthorizedError) as exc_info:
        token_service.verify_access_token(refresh_token)
    assert exc_info.value.code == "TOKEN_INVALID"

    # Token hoàn toàn không có claim 'type'
    payload_no_type = {
        "sub": "42",
        "role": "admin",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    no_type_token = jwt.encode(payload_no_type, TEST_SECRET_KEY, algorithm="HS256")

    with pytest.raises(UnauthorizedError) as exc_info:
        token_service.verify_access_token(no_type_token)
    assert exc_info.value.code == "TOKEN_INVALID"


def test_17_jwt_errors_do_not_leak_secret_or_internal_info(token_service: AdminTokenService):
    """17. Lỗi JWT tuyệt đối không làm rò rỉ secret key hoặc thông tin traceback nội bộ."""
    # Gửi token hỏng
    try:
        token_service.verify_access_token("corrupted.signature.token")
    except UnauthorizedError as exc:
        err_msg = exc.message
        assert TEST_SECRET_KEY not in err_msg
        assert "traceback" not in err_msg.lower()
        assert "pymysql" not in err_msg.lower()
        assert "secret" not in err_msg.lower()

    # Gửi token hết hạn
    expired_token = token_service.create_access_token(sub="1", role="admin", expires_delta=timedelta(minutes=-1))
    try:
        token_service.verify_access_token(expired_token)
    except UnauthorizedError as exc:
        err_msg = exc.message
        assert TEST_SECRET_KEY not in err_msg
        assert "traceback" not in err_msg.lower()


def test_18_token_service_does_not_create_engine_or_session():
    """18. Token Service hoàn toàn độc lập với CSDL (không import hay tạo Engine/Session)."""
    service_file = BACKEND_DIR / "app" / "services" / "admin_token.py"
    assert service_file.exists(), "admin_token.py phải tồn tại"

    tree = ast.parse(service_file.read_text(encoding="utf-8"))

    # Duyệt AST để kiểm tra các import và gọi hàm CSDL
    forbidden_imports = {
        "create_engine",
        "sessionmaker",
        "SessionLocal",
        "get_db",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in forbidden_imports, f"admin_token.py không được import {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.module and ("database" in node.module or "dependencies" in node.module):
                for alias in node.names:
                    assert alias.name not in forbidden_imports, f"admin_token.py không được import {alias.name}"


# =============================================================================
# CÁC TEST BỔ SUNG: ADMINAUTHRESULT, DICT, KWARGS, VALIDATION & CONFIG ERROR
# =============================================================================

def test_token_service_with_admin_auth_result(token_service: AdminTokenService):
    """Kiểm tra tương thích hoàn hảo với đối tượng AdminAuthResult từ Step 3.4.1."""
    auth_result = AdminAuthResult(
        id=99,
        username="auditor_user",
        email="audit@enterprise.local",
        role="auditor",
        is_active=True,
    )
    token = token_service.create_access_token(auth_result)
    claims = token_service.verify_access_token(token)

    assert claims.sub == "99"
    assert claims.role == "auditor"


def test_token_service_with_kwargs_and_dict(token_service: AdminTokenService):
    """Kiểm tra phát hành token bằng dict hoặc kwargs tường minh."""
    # Truyền qua kwargs
    token_kwargs = token_service.create_access_token(sub="105", role="network_admin")
    claims_kwargs = token_service.verify_access_token(token_kwargs)
    assert claims_kwargs.sub == "105"
    assert claims_kwargs.role == "network_admin"

    # Truyền qua dict
    token_dict = token_service.create_access_token({"id": 200, "role": "operator"})
    claims_dict = token_service.verify_access_token(token_dict)
    assert claims_dict.sub == "200"
    assert claims_dict.role == "operator"


def test_token_creation_validation_errors(token_service: AdminTokenService):
    """Kiểm tra Validation Error khi thiếu sub hoặc role khi tạo token."""
    with pytest.raises(ValidationError) as exc_sub:
        token_service.create_access_token(sub="", role="admin")
    assert exc_sub.value.code == "VALIDATION_ERROR"

    with pytest.raises(ValidationError) as exc_role:
        token_service.create_access_token(sub="1", role="")
    assert exc_role.value.code == "VALIDATION_ERROR"


def test_token_service_handles_missing_secret_key():
    """Kiểm tra xử lý ServiceUnavailableError khi secret_key rỗng."""
    service_no_secret = AdminTokenService(secret_key="")

    with pytest.raises(ServiceUnavailableError) as exc_create:
        service_no_secret.create_access_token(sub="1", role="admin")
    assert exc_create.value.code == "SERVICE_UNAVAILABLE"

    with pytest.raises(ServiceUnavailableError) as exc_verify:
        service_no_secret.verify_access_token("some.token.here")
    assert exc_verify.value.code == "SERVICE_UNAVAILABLE"
