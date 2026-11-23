"""
Admin Token Service cho Dashboard Quản trị (Phase 0B - Step 3.4.2).
Chịu trách nhiệm:
1. Phát hành JWT Access Token cho Dashboard Admin đã xác thực danh tính.
2. Xác minh chữ ký số (HS256), thời hạn (exp = 30 phút), và tính toàn vẹn của các claims.
3. Kiểm tra bắt buộc các claims tối thiểu:
   - sub: ID hoặc định danh duy nhất của Admin (dạng chuỗi).
   - role: Vai trò của Admin (superadmin, it_admin, auditor,...).
   - type: "access" (phân biệt Access Token với các loại token khác).
   - iat, exp: Thời điểm phát hành và hết hạn.
4. Bảo vệ an ninh:
   - Tuyệt đối không chứa password, password_hash, DB credentials hay bí mật hệ thống trong claims.
   - Không chứa thông tin cá nhân dư thừa (email) khi không có lý do nghiệp vụ.
   - Từ chối token hết hạn, sai chữ ký, sai định dạng, thiếu claims hoặc thuật toán không được phép (alg=none).
   - Chuyển hóa lỗi JWT thành Business Exceptions an toàn (UnauthorizedError, ServiceUnavailableError).
   - Hoàn toàn độc lập với CSDL (không tạo Engine, Session hay kết nối database).
"""

from datetime import timedelta
import logging
from typing import Any, Dict, Optional, Union

from app.core.config import settings
from app.core.exceptions import ServiceUnavailableError, UnauthorizedError, ValidationError
from app.core.security import (
    TokenConfigError,
    TokenExpiredError,
    TokenInvalidError,
    create_access_token as security_create_access_token,
    verify_access_token as security_verify_access_token,
)

logger = logging.getLogger(__name__)


class AdminTokenClaims(dict):
    """
    DTO đại diện cho các JWT Claims an toàn đã được giải mã và xác minh.
    Kế thừa dict để tương thích 100% với dictionary access (`claims['sub']`),
    đồng thời hỗ trợ attribute access (`claims.sub`).
    """

    def __init__(self, sub: str, role: str, type: str, iat: int, exp: int, **extra: Any) -> None:
        super().__init__(sub=sub, role=role, type=type, iat=iat, exp=exp, **extra)
        self.sub = sub
        self.role = role
        self.type = type
        self.iat = iat
        self.exp = exp

    def to_dict(self) -> Dict[str, Any]:
        """Trả về bản sao dictionary của claims."""
        return dict(self)


class AdminTokenService:
    """
    Dịch vụ phát hành và xác minh JWT Access Token cho quản trị viên Dashboard.
    Tái sử dụng các hàm mật mã chuẩn trong app.core.security.
    """

    def __init__(self, secret_key: Optional[str] = None) -> None:
        """
        Khởi tạo AdminTokenService.

        Args:
            secret_key: Khóa bí mật tùy chọn để ký và xác minh token (hữu ích cho unit test).
                        Nếu None, service sẽ tự động dùng settings.JWT_SECRET_KEY.
        """
        self.secret_key = secret_key

    def create_access_token(
        self,
        admin: Optional[Any] = None,
        *,
        sub: Optional[Union[str, int]] = None,
        role: Optional[str] = None,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """
        Phát hành JWT Access Token cho Admin với thời hạn chuẩn 30 phút (HS256).

        Args:
            admin: Đối tượng Admin đã xác thực (AdminAuthResult, AppAdmin hoặc dict chứa id/role).
            sub: Định danh duy nhất của Admin (chỉ dùng nếu không truyền admin).
            role: Vai trò của Admin (chỉ dùng nếu không truyền admin).
            expires_delta: Thời hạn tùy chọn (mặc định lấy từ settings.ACCESS_TOKEN_EXPIRE_MINUTES = 30 phút).

        Returns:
            str: Chuỗi JWT Access Token đã ký.

        Raises:
            ValidationError: Khi thiếu hoặc sai lệch thông tin sub/role (HTTP 422).
            ServiceUnavailableError: Khi khóa bí mật JWT_SECRET_KEY chưa được cấu hình (HTTP 503).
        """
        # 1. Trích xuất sub (Admin ID) và role từ đối tượng admin hoặc tham số truyền vào
        sub_val: Optional[str] = None
        role_val: Optional[str] = None

        if admin is not None:
            # Hỗ trợ AdminAuthResult, AppAdmin ORM model, hoặc dict
            extracted_id = getattr(admin, "id", None)
            if extracted_id is None and isinstance(admin, dict):
                extracted_id = admin.get("id") or admin.get("sub")

            if extracted_id is not None:
                sub_val = str(extracted_id)

            extracted_role = getattr(admin, "role", None)
            if extracted_role is None and isinstance(admin, dict):
                extracted_role = admin.get("role")

            if extracted_role is not None:
                role_val = str(extracted_role)

        # Nếu truyền qua keyword arguments, ưu tiên ghi đè/bổ sung
        if sub is not None:
            sub_val = str(sub)
        if role is not None:
            role_val = str(role)

        # 2. Validation claims đầu vào
        if not sub_val or not isinstance(sub_val, str) or not sub_val.strip():
            raise ValidationError(
                message="Claim định danh 'sub' không được để trống và phải là chuỗi hợp lệ.",
                code="VALIDATION_ERROR",
            )

        if not role_val or not isinstance(role_val, str) or not role_val.strip():
            raise ValidationError(
                message="Claim vai trò 'role' không được để trống và phải là chuỗi hợp lệ.",
                code="VALIDATION_ERROR",
            )

        # 3. Chuẩn bị payload (tối thiểu và an toàn, tuyệt đối không chứa password hay secret)
        payload: Dict[str, Any] = {
            "sub": sub_val.strip(),
            "role": role_val.strip(),
            "type": "access",
        }

        # 4. Phát hành token thông qua module security chuẩn
        try:
            token = security_create_access_token(
                data=payload,
                expires_delta=expires_delta,
                secret_key=self.secret_key,
            )
            return token
        except TokenConfigError as exc:
            logger.error("Lỗi cấu hình JWT Secret Key khi tạo token: %s", exc)
            raise ServiceUnavailableError(
                message="Dịch vụ xác thực token hiện không khả dụng do thiếu cấu hình bảo mật.",
                code="SERVICE_UNAVAILABLE",
            ) from exc

    def verify_access_token(self, token: str) -> AdminTokenClaims:
        """
        Xác minh và giải mã JWT Access Token.
        Kiểm tra chữ ký (HS256), thời hạn (exp), và tính hợp lệ của các claims (sub, role, type).

        Args:
            token: Chuỗi JWT Access Token cần xác minh.

        Returns:
            AdminTokenClaims: Đối tượng DTO chứa các claims đã được kiểm định an toàn.

        Raises:
            UnauthorizedError: Khi token hết hạn (401, TOKEN_EXPIRED) hoặc không hợp lệ (401, TOKEN_INVALID).
            ServiceUnavailableError: Khi khóa bí mật chưa được cấu hình (503).
        """
        # 1. Kiểm tra định dạng đầu vào cơ bản
        if not token or not isinstance(token, str) or not token.strip():
            raise UnauthorizedError(
                message="Token truy cập không được để trống và phải là chuỗi ký tự.",
                code="TOKEN_INVALID",
            )

        clean_token = token.strip()

        # 2. Giải mã và kiểm tra chữ ký thông qua core/security.py
        try:
            payload = security_verify_access_token(
                token=clean_token,
                secret_key=self.secret_key,
            )
        except TokenExpiredError as exc:
            logger.warning("Xác minh JWT thất bại: Token đã hết hạn.")
            raise UnauthorizedError(
                message="Token truy cập đã hết hạn. Vui lòng đăng nhập lại.",
                code="TOKEN_EXPIRED",
            ) from exc
        except TokenInvalidError as exc:
            logger.warning("Xác minh JWT thất bại: Token không hợp lệ hoặc sai chữ ký.")
            raise UnauthorizedError(
                message="Token truy cập không hợp lệ hoặc đã bị chỉnh sửa.",
                code="TOKEN_INVALID",
            ) from exc
        except TokenConfigError as exc:
            logger.error("Lỗi cấu hình JWT Secret Key khi giải mã token: %s", exc)
            raise ServiceUnavailableError(
                message="Dịch vụ xác thực token hiện không khả dụng do cấu hình.",
                code="SERVICE_UNAVAILABLE",
            ) from exc
        except Exception as exc:
            logger.error("Lỗi không mong đợi trong quá trình giải mã token: %s", exc, exc_info=True)
            raise UnauthorizedError(
                message="Xác minh token truy cập thất bại.",
                code="TOKEN_INVALID",
            ) from exc

        # 3. Kiểm tra tính hợp lệ của các Claims bắt buộc
        # A. Kiểm tra 'sub'
        sub = payload.get("sub")
        if not sub or not isinstance(sub, str) or not sub.strip():
            logger.warning("Xác minh JWT thất bại: Token thiếu hoặc sai định dạng claim 'sub'.")
            raise UnauthorizedError(
                message="Token truy cập thiếu thông tin định danh hợp lệ (sub).",
                code="TOKEN_INVALID",
            )

        # B. Kiểm tra 'role'
        role = payload.get("role")
        if not role or not isinstance(role, str) or not role.strip():
            logger.warning("Xác minh JWT thất bại: Token thiếu hoặc sai định dạng claim 'role'.")
            raise UnauthorizedError(
                message="Token truy cập thiếu thông tin vai trò hợp lệ (role).",
                code="TOKEN_INVALID",
            )

        # C. Kiểm tra 'type' (bắt buộc phải là 'access')
        token_type = payload.get("type")
        if token_type != "access":
            logger.warning(
                "Xác minh JWT thất bại: Loại token không hợp lệ (nhận '%s', yêu cầu 'access').",
                token_type,
            )
            raise UnauthorizedError(
                message="Loại token không hợp lệ cho thao tác này (yêu cầu Access Token).",
                code="TOKEN_INVALID",
            )

        # D. Kiểm tra thời hạn 'iat' và 'exp'
        iat = payload.get("iat")
        exp = payload.get("exp")
        if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)):
            logger.warning("Xác minh JWT thất bại: Claims thời gian 'iat'/'exp' không đúng kiểu số.")
            raise UnauthorizedError(
                message="Token truy cập chứa mốc thời gian không hợp lệ.",
                code="TOKEN_INVALID",
            )

        # 4. Trả về DTO claims an toàn
        return AdminTokenClaims(
            sub=sub.strip(),
            role=role.strip(),
            type=str(token_type),
            iat=int(iat),
            exp=int(exp),
        )
