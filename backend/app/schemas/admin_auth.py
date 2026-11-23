"""
Pydantic Schemas cho Dashboard Admin Authentication (Phase 0B - Step 3.4.5).
Chịu trách nhiệm:
1. Validate dữ liệu đầu vào cho yêu cầu đăng nhập quản trị viên (AdminLoginRequest).
2. Định dạng dữ liệu đầu ra an toàn sau khi xác thực (AdminLoginResponse, AdminInfoResponse).
3. Tuyệt đối không chứa hoặc serialize các trường nhạy cảm (password, password_hash).
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class AdminLoginRequest(BaseModel):
    """Schema dữ liệu yêu cầu đăng nhập từ Dashboard Admin."""

    username: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Tên đăng nhập của quản trị viên",
    )
    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Mật khẩu của quản trị viên",
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Tên đăng nhập phải là chuỗi ký tự.")
        stripped = v.strip()
        if not stripped:
            raise ValueError("Tên đăng nhập không được để trống hoặc chỉ chứa khoảng trắng.")
        return stripped

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Mật khẩu phải là chuỗi ký tự.")
        if not v:
            raise ValueError("Mật khẩu không được để trống.")
        # Bảo toàn nguyên vẹn giá trị gốc của password, không tự ý strip khoảng trắng
        return v


class AdminInfoResponse(BaseModel):
    """DTO thông tin quản trị viên an toàn trả về trong response đăng nhập."""

    id: int
    username: str
    email: Optional[str] = None
    role: str
    is_active: bool
    created_at: Optional[datetime] = None


class AdminLoginResponse(BaseModel):
    """Schema dữ liệu phản hồi đăng nhập thành công theo chuẩn OAuth2 Bearer Token."""

    access_token: str = Field(..., description="JWT Access Token đã ký")
    token_type: str = Field(default="bearer", description="Loại token xác thực")
    expires_in: int = Field(..., description="Thời gian sống của token tính bằng giây")
    admin: AdminInfoResponse = Field(..., description="Thông tin an toàn của quản trị viên đã đăng nhập")


class AdminChangePasswordRequest(BaseModel):
    """Schema dữ liệu yêu cầu đổi mật khẩu từ Dashboard Admin đang đăng nhập."""

    current_password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Mật khẩu hiện tại của quản trị viên",
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Mật khẩu mới (từ 8 đến 128 ký tự)",
    )
    confirm_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Xác nhận mật khẩu mới (phải khớp hoàn toàn với new_password)",
    )

    @field_validator("current_password", "new_password", "confirm_password")
    @classmethod
    def validate_password_not_empty(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("Mật khẩu phải là chuỗi ký tự.")
        if not v:
            raise ValueError("Mật khẩu không được để trống.")
        # Bảo toàn nguyên vẹn giá trị gốc của mật khẩu, không tự ý strip khoảng trắng
        return v

    @model_validator(mode="after")
    def validate_password_confirmation(self) -> "AdminChangePasswordRequest":
        if self.new_password != self.confirm_password:
            raise ValueError("Mật khẩu xác nhận không khớp với mật khẩu mới.")
        return self


class AdminChangePasswordResponse(BaseModel):
    """Schema dữ liệu phản hồi sau khi đổi mật khẩu thành công."""

    message: str = Field(
        default="Đổi mật khẩu thành công.",
        description="Thông điệp xác nhận thao tác thành công",
    )
    admin: AdminInfoResponse = Field(
        ...,
        description="Thông tin an toàn của quản trị viên sau khi cập nhật",
    )
