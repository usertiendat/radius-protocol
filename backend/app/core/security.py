import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from app.core.config import settings

# Hằng số cấu hình thuật toán băm mật khẩu chuẩn
PBKDF2_ALGORITHM = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 310_000
SALT_BYTES = 16


class SecurityError(Exception):
    """Lớp ngoại lệ cơ sở cho các lỗi liên quan đến bảo mật và token."""
    pass


class TokenConfigError(SecurityError):
    """Ngoại lệ khi khóa bí mật JWT chưa được thiết lập."""
    pass


class TokenExpiredError(SecurityError):
    """Ngoại lệ khi token đã hết hạn (exp)."""
    pass


class TokenInvalidError(SecurityError):
    """Ngoại lệ khi token không hợp lệ (sai chữ ký, sai cấu trúc)."""
    pass


def hash_password(password: str) -> str:
    """
    Băm mật khẩu sử dụng PBKDF2-HMAC-SHA256 với salt ngẫu nhiên và 310.000 vòng lặp.

    Định dạng kết quả:
    pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not password or not isinstance(password, str):
        raise ValueError("Mật khẩu không được để trống và phải là chuỗi ký tự.")

    salt = secrets.token_bytes(SALT_BYTES)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return f"{PBKDF2_ALGORITHM}${PBKDF2_ITERATIONS}${salt.hex()}${password_hash.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Xác minh mật khẩu dạng rõ với chuỗi băm.
    So sánh an toàn chống tấn công timing attack bằng hmac.compare_digest.
    Xử lý an toàn mọi đầu vào sai lệch hoặc chuỗi băm hỏng (không gây sập ứng dụng).
    """
    if not plain_password or not hashed_password:
        return False

    if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
        return False

    try:
        parts = hashed_password.split("$")
        
        # Định dạng chuẩn mới: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
        if len(parts) == 4 and parts[0] == PBKDF2_ALGORITHM:
            algorithm = parts[0]
            iterations = int(parts[1])
            salt = bytes.fromhex(parts[2])
            expected_hash = parts[3]

            if iterations < 1:
                return False

            computed_hash = hashlib.pbkdf2_hmac(
                "sha256",
                plain_password.encode("utf-8"),
                salt,
                iterations,
            ).hex()

            return hmac.compare_digest(computed_hash, expected_hash)

        # Hỗ trợ tương thích ngược định dạng legacy: <salt_hex>$<hash_hex> (310.000 iterations)
        elif len(parts) == 2:
            salt = bytes.fromhex(parts[0])
            expected_hash = parts[1]

            computed_hash = hashlib.pbkdf2_hmac(
                "sha256",
                plain_password.encode("utf-8"),
                salt,
                PBKDF2_ITERATIONS,
            ).hex()

            return hmac.compare_digest(computed_hash, expected_hash)

        return False
    except Exception:
        # Bắt toàn bộ lỗi giải mã hex hoặc định dạng không hợp lệ, trả về False an toàn
        return False


def _get_jwt_secret_key() -> str:
    """Lấy và kiểm tra tính hợp lệ của khóa bí mật JWT."""
    secret_key = settings.JWT_SECRET_KEY
    if not secret_key or not secret_key.strip():
        raise TokenConfigError(
            "JWT_SECRET_KEY chưa được cấu hình hoặc chỉ chứa khoảng trắng. "
            "Vui lòng thiết lập biến môi trường JWT_SECRET_KEY."
        )
    return secret_key


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
    secret_key: Optional[str] = None,
) -> str:
    """
    Tạo JWT Access Token chứa dữ liệu payload, thời điểm phát hành (iat) và hết hạn (exp).
    """
    signing_key = secret_key if secret_key is not None else _get_jwt_secret_key()
    if not signing_key or not signing_key.strip():
        raise TokenConfigError("Khóa bí mật ký JWT không hợp lệ.")

    to_encode = data.copy()
    now = datetime.now(timezone.utc)

    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    })

    encoded_jwt = jwt.encode(
        to_encode,
        signing_key,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def verify_access_token(
    token: str,
    secret_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Giải mã và xác minh tính toàn vẹn của JWT Access Token.
    Ném TokenExpiredError nếu token hết hạn, TokenInvalidError nếu chữ ký/dữ liệu sai.
    """
    if not token or not isinstance(token, str):
        raise TokenInvalidError("Token không được để trống và phải là chuỗi ký tự.")

    verification_key = secret_key if secret_key is not None else _get_jwt_secret_key()
    if not verification_key or not verification_key.strip():
        raise TokenConfigError("Khóa bí mật giải mã JWT không hợp lệ.")

    try:
        payload = jwt.decode(
            token,
            verification_key,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError("Token truy cập đã hết hạn.") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenInvalidError("Token không hợp lệ hoặc đã bị thay đổi.") from exc
