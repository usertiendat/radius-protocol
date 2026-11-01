import logging
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pyrad2.client import Client, Timeout
from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary

logger = logging.getLogger(__name__)

# Xác định đường dẫn độc lập với thư mục làm việc hiện tại
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"
DICT_PATH = BACKEND_DIR / "radius_dictionary"

# Nạp file .env ở thư mục gốc nếu tồn tại
load_dotenv(ENV_PATH)

# Cache đối tượng Dictionary để tối ưu hiệu năng
_cached_dictionary: Optional[Dictionary] = None


class RadiusError(Exception):
    """Lớp ngoại lệ cơ sở cho các lỗi liên quan đến RADIUS."""
    pass


class RadiusConfigError(RadiusError):
    """Ngoại lệ khi thiếu file cấu hình .env hoặc file radius_dictionary."""
    pass


class RadiusConnectionError(RadiusError):
    """Ngoại lệ khi xảy ra timeout hoặc lỗi kết nối socket đến FreeRADIUS."""
    pass


class RadiusAuthenticationFailed(RadiusError):
    """Ngoại lệ khi FreeRADIUS phản hồi Access-Reject."""
    pass


def get_dictionary() -> Dictionary:
    """Nạp và cache đối tượng Dictionary từ file radius_dictionary."""
    global _cached_dictionary
    if _cached_dictionary is not None:
        return _cached_dictionary

    if not DICT_PATH.is_file():
        logger.error("Không tìm thấy file từ điển RADIUS tại: %s", DICT_PATH)
        raise RadiusConfigError(f"Không tìm thấy file từ điển RADIUS tại {DICT_PATH}")

    try:
        _cached_dictionary = Dictionary(str(DICT_PATH))
        return _cached_dictionary
    except Exception as exc:
        logger.error("Lỗi khi nạp file từ điển RADIUS: %s", exc)
        raise RadiusConfigError("Không thể nạp file từ điển RADIUS.") from exc


def close_client(client: Client) -> None:
    """
    Dọn dẹp an toàn tài nguyên mạng của Client theo cơ chế của pyrad2 3.2.
    pyrad2 cung cấp _close_socket() (được dùng nội bộ trong Client.bind)
    để hủy đăng ký khỏi selector/poll và đóng UDP socket.
    Phương thức này kiểm tra `if self._socket:`, do đó an toàn và idempotent khi gọi nhiều lần.
    """
    try:
        if hasattr(client, "_close_socket") and callable(client._close_socket):
            client._close_socket()
        elif hasattr(client, "_socket") and client._socket:
            client._socket.close()
            client._socket = None
    except Exception:
        # Bỏ qua lỗi dọn dẹp để không làm át ngoại lệ chính trong khối finally
        pass


def authenticate_radius(username: str, password: str) -> None:
    """
    Gửi Access-Request xác thực thông tin đăng nhập đến máy chủ FreeRADIUS.

    Quy tắc:
    - Trả về None nếu FreeRADIUS phản hồi Access-Accept (xác thực thành công).
    - Ném RadiusAuthenticationFailed nếu nhận Access-Reject.
    - Ném RadiusConnectionError nếu timeout hoặc gặp lỗi mạng/socket.
    - Ném RadiusConfigError nếu thiếu thông tin cấu hình hoặc file từ điển.
    """
    server = os.getenv("RADIUS_SERVER")
    secret = os.getenv("RADIUS_SECRET")

    if not server or not secret:
        logger.error("Cấu hình RADIUS_SERVER hoặc RADIUS_SECRET chưa được thiết lập trong .env")
        raise RadiusConfigError("Cấu hình máy chủ RADIUS không đầy đủ.")

    try:
        auth_port = int(os.getenv("RADIUS_AUTH_PORT", "1812"))
        timeout = int(os.getenv("RADIUS_TIMEOUT", "3"))
        retries = int(os.getenv("RADIUS_RETRIES", "1"))
    except ValueError as exc:
        logger.error("Giá trị cấu hình port/timeout/retries không hợp lệ: %s", exc)
        raise RadiusConfigError("Giá trị cấu hình RADIUS không hợp lệ.") from exc

    dict_obj = get_dictionary()

    client = Client(
        server=server,
        authport=auth_port,
        secret=secret.encode("utf-8"),
        dict=dict_obj,
        timeout=timeout,
        retries=retries,
    )

    response = None
    try:
        request = client.create_auth_packet(User_Name=username)
        # Mã hóa mật khẩu PAP theo chuẩn RADIUS
        request["User-Password"] = request.pw_crypt(password)

        response = client.send_packet(request)
    except (Timeout, TimeoutError) as exc:
        logger.warning(
            "Timeout khi chờ phản hồi từ FreeRADIUS cho người dùng: %s",
            username,
        )
        raise RadiusConnectionError(
            "Máy chủ RADIUS không phản hồi (timeout)."
        ) from exc
    except OSError as exc:
        logger.warning(
            "Lỗi kết nối socket RADIUS cho người dùng %s: %s",
            username,
            type(exc).__name__,
        )
        raise RadiusConnectionError(
            "Lỗi kết nối mạng tới máy chủ RADIUS."
        ) from exc
    except Exception as exc:
        logger.error(
            "Lỗi giao thức RADIUS không mong muốn: %s",
            type(exc).__name__,
        )
        raise RadiusConnectionError(
            "Lỗi giao tiếp máy chủ RADIUS."
        ) from exc
    finally:
        close_client(client)

    if response is None:
        logger.warning("Không nhận được packet phản hồi từ RADIUS server.")
        raise RadiusConnectionError(
            "Không nhận được phản hồi từ máy chủ RADIUS."
        )

    if response.code == PacketType.AccessAccept:
        logger.info("Xác thực RADIUS thành công cho người dùng: %s", username)
        return
    elif response.code == PacketType.AccessReject:
        logger.warning(
            "Xác thực RADIUS bị từ chối (Access-Reject) cho người dùng: %s",
            username,
        )
        raise RadiusAuthenticationFailed(
            "Tên đăng nhập hoặc mật khẩu không hợp lệ."
        )
    else:
        logger.warning("Nhận mã phản hồi RADIUS không mong muốn: %s", response.code)
        raise RadiusConnectionError(
            "Nhận phản hồi không mong muốn từ máy chủ RADIUS."
        )
