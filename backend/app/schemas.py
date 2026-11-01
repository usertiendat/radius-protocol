from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    """Schema dữ liệu yêu cầu đăng nhập từ client."""

    username: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Tên đăng nhập RADIUS",
    )
    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Mật khẩu RADIUS",
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError(
                "Tên đăng nhập không được để trống hoặc chỉ chứa khoảng trắng."
            )
        return stripped

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not v.strip():
            raise ValueError(
                "Mật khẩu không được để trống hoặc chỉ chứa khoảng trắng."
            )
        # Giữ nguyên giá trị gốc của mật khẩu, bảo toàn mọi ký tự và khoảng trắng bên trong
        return v


class LoginResponse(BaseModel):
    """Schema dữ liệu phản hồi đăng nhập thành công."""

    success: bool = True
    message: str = "Xác thực thành công."
