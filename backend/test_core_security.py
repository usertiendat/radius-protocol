"""
Bộ kiểm thử đơn vị cho Core Configuration và Security Module (Phase 0B - Step 1).
Bảo đảm tính độc lập hoàn toàn, không phụ thuộc cơ sở dữ liệu hay mạng ngoài.
"""

import sys
from datetime import timedelta
from pathlib import Path

# Đảm bảo backend có trong sys.path
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from app.core.config import Settings, settings
from app.core.security import (
    PBKDF2_ALGORITHM,
    PBKDF2_ITERATIONS,
    TokenConfigError,
    TokenExpiredError,
    TokenInvalidError,
    create_access_token,
    hash_password,
    verify_access_token,
    verify_password,
)

TEST_SECRET = "super-secure-test-jwt-secret-key-for-unit-testing-32chars"


# -----------------------------------------------------------------------------
# 1. KIỂM THỬ BĂM VÀ XÁC MINH MẬT KHẨU (PBKDF2)
# -----------------------------------------------------------------------------

def test_hash_and_verify_correct_password():
    """Kiểm tra băm và xác minh thành công với đúng mật khẩu."""
    password = "CorrectSecretPassword123!@#"
    hashed = hash_password(password)

    # Đảm bảo định dạng chuẩn pbkdf2_sha256$310000$<salt>$<hash>
    parts = hashed.split("$")
    assert len(parts) == 4
    assert parts[0] == PBKDF2_ALGORITHM
    assert int(parts[1]) == PBKDF2_ITERATIONS
    assert len(parts[2]) == 32  # 16 bytes = 32 hex chars
    assert len(parts[3]) == 64  # sha256 = 32 bytes = 64 hex chars

    # Xác minh đúng mật khẩu
    assert verify_password(password, hashed) is True


def test_verify_wrong_password_returns_false():
    """Kiểm tra xác minh sai mật khẩu trả về False."""
    password = "CorrectPassword123"
    wrong_password = "WrongPassword456"
    hashed = hash_password(password)

    assert verify_password(wrong_password, hashed) is False


def test_two_hashes_of_same_password_have_different_salts():
    """Hai lần băm cùng một mật khẩu phải sinh ra salt và chuỗi băm khác nhau."""
    password = "IdenticalPassword789"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    assert hash1 != hash2
    salt1 = hash1.split("$")[2]
    salt2 = hash2.split("$")[2]
    assert salt1 != salt2

    # Cả 2 hash đều phải verify thành công với mật khẩu gốc
    assert verify_password(password, hash1) is True
    assert verify_password(password, hash2) is True


def test_password_hashing_invalid_inputs():
    """Kiểm tra xử lý an toàn với các đầu vào bất thường."""
    # Hash với chuỗi rỗng
    with pytest.raises(ValueError):
        hash_password("")

    # Verify với đầu vào rỗng hoặc None
    assert verify_password("", "some_hash") is False
    assert verify_password("pass", "") is False
    assert verify_password(None, "some_hash") is False
    assert verify_password("pass", None) is False

    # Verify với chuỗi hash hỏng, không đúng định dạng
    assert verify_password("pass", "malformed_hash_without_dollar") is False
    assert verify_password("pass", "pbkdf2_sha256$invalid_iter$salt$hash") is False
    assert verify_password("pass", "pbkdf2_sha256$310000$not_hex_salt$hash") is False


def test_verify_legacy_hash_format():
    """Kiểm tra tính tương thích ngược với định dạng legacy: <salt_hex>$<hash_hex>."""
    import hashlib
    salt = bytes.fromhex("0123456789abcdef0123456789abcdef")
    legacy_hash = hashlib.pbkdf2_hmac(
        "sha256",
        "LegacyPass123".encode("utf-8"),
        salt,
        310_000,
    ).hex()
    legacy_string = f"{salt.hex()}${legacy_hash}"

    assert verify_password("LegacyPass123", legacy_string) is True
    assert verify_password("WrongPass", legacy_string) is False


# -----------------------------------------------------------------------------
# 2. KIỂM THỬ TẠO VÀ XÁC MINH JWT TOKEN (PYJWT)
# -----------------------------------------------------------------------------

def test_jwt_encode_and_decode_success():
    """Kiểm tra mã hóa và giải mã JWT thành công."""
    payload_data = {"sub": "admin_user", "role": "superadmin", "custom_id": 42}
    token = create_access_token(
        data=payload_data,
        expires_delta=timedelta(minutes=15),
        secret_key=TEST_SECRET,
    )

    assert isinstance(token, str)
    assert len(token) > 20

    # Giải mã
    decoded = verify_access_token(token, secret_key=TEST_SECRET)
    assert decoded["sub"] == "admin_user"
    assert decoded["role"] == "superadmin"
    assert decoded["custom_id"] == 42
    assert "iat" in decoded
    assert "exp" in decoded
    assert decoded["exp"] > decoded["iat"]


def test_jwt_expired_token_rejected():
    """Kiểm tra token đã hết hạn bị từ chối bằng TokenExpiredError."""
    payload_data = {"sub": "expired_admin"}
    # Tạo token đã hết hạn 5 phút trước
    expired_token = create_access_token(
        data=payload_data,
        expires_delta=timedelta(minutes=-5),
        secret_key=TEST_SECRET,
    )

    with pytest.raises(TokenExpiredError):
        verify_access_token(expired_token, secret_key=TEST_SECRET)


def test_jwt_invalid_signature_rejected():
    """Kiểm tra token bị ký bởi secret khác bị từ chối bằng TokenInvalidError."""
    payload_data = {"sub": "test_user"}
    token = create_access_token(data=payload_data, secret_key=TEST_SECRET)

    # Thử giải mã bằng khóa bí mật khác
    another_secret = "another-wrong-secret-key-32-chars-long"
    with pytest.raises(TokenInvalidError):
        verify_access_token(token, secret_key=another_secret)


def test_jwt_malformed_token_rejected():
    """Kiểm tra token bị thay đổi nội dung hoặc chuỗi rác bị từ chối."""
    with pytest.raises(TokenInvalidError):
        verify_access_token("this.is.not.a.valid.jwt.token", secret_key=TEST_SECRET)

    with pytest.raises(TokenInvalidError):
        verify_access_token("", secret_key=TEST_SECRET)


def test_jwt_missing_secret_handled_safely():
    """Kiểm tra khi thiếu secret key sẽ ném TokenConfigError an toàn."""
    with pytest.raises(TokenConfigError):
        create_access_token({"sub": "admin"}, secret_key="")

    with pytest.raises(TokenConfigError):
        verify_access_token("some.token.here", secret_key="")


# -----------------------------------------------------------------------------
# 3. KIỂM THỬ CORE CONFIGURATION (SETTINGS)
# -----------------------------------------------------------------------------

def test_settings_loaded_and_database_url_constructed():
    """Kiểm tra Settings nạp cấu hình hợp lệ và chuỗi database_url chuẩn."""
    assert settings.APP_NAME is not None
    assert settings.DB_PORT == 3306
    assert "mysql+pymysql://" in settings.database_url
    assert "radius_db" in settings.database_url


def test_settings_repr_masks_secrets():
    """Kiểm tra chuỗi biểu diễn của Settings không để lộ mật khẩu hay secret."""
    repr_str = repr(settings)
    assert "Settings(" in repr_str
    # Không xuất hiện các từ khóa nhạy cảm trong representation
    assert "JWT_SECRET_KEY=" not in repr_str
    assert "DB_PASSWORD=" not in repr_str
    assert "RADIUS_SECRET=" not in repr_str
