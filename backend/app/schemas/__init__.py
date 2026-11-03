"""
Pydantic Schemas Package cho RADIUS Enterprise Authentication & Access Control.
Chịu trách nhiệm:
- Data Validation cho các Request payload từ Client.
- Serialization và Formatting cho các Response DTOs.
- Ngăn chặn triệt để việc rò rỉ dữ liệu nhạy cảm (password, secret, hash).

Ghi chú tương thích:
- Nạp và re-export các schema hiện hữu từ backend/app/schemas.py (LoginRequest, LoginResponse)
  để bảo đảm 100% tương thích ngược với các router và test hiện hành.
"""

from pathlib import Path
import importlib.util

# Tự động nạp và re-export từ schemas.py hiện hữu nếu tồn tại
_legacy_schemas_file = Path(__file__).resolve().parent.parent / "schemas.py"
if _legacy_schemas_file.exists():
    _spec = importlib.util.spec_from_file_location("_legacy_schemas", _legacy_schemas_file)
    if _spec and _spec.loader:
        _mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        LoginRequest = getattr(_mod, "LoginRequest", None)
        LoginResponse = getattr(_mod, "LoginResponse", None)

from .user import UserCreate, UserResponse, UserUpdate
from .group import GroupAttribute, GroupCreate, GroupResponse, GroupUpdate
from .nas import NASCreate, NASResponse

__all__ = [
    "LoginRequest",
    "LoginResponse",
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "GroupAttribute",
    "GroupCreate",
    "GroupUpdate",
    "GroupResponse",
    "NASCreate",
    "NASResponse",
]
