
import os
from pathlib import Path

from dotenv import load_dotenv
from pyrad2.client import Client
from pyrad2.constants import PacketType
from pyrad2.dictionary import Dictionary


# Đọc file .env ở thư mục gốc dự án
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

RADIUS_SERVER = os.getenv("RADIUS_SERVER")
RADIUS_AUTH_PORT = int(os.getenv("RADIUS_AUTH_PORT", "1812"))
RADIUS_SECRET = os.getenv("RADIUS_SECRET")

if not RADIUS_SERVER or not RADIUS_SECRET:
    raise RuntimeError(
        "Thiếu RADIUS_SERVER hoặc RADIUS_SECRET trong file .env"
    )

dictionary_path = PROJECT_ROOT / "backend" / "radius_dictionary"

client = Client(
    server=RADIUS_SERVER,
    authport=RADIUS_AUTH_PORT,
    secret=RADIUS_SECRET.encode("utf-8"),
    dict=Dictionary(str(dictionary_path)),
    timeout=3,
    retries=1,
)

# Tạo yêu cầu xác thực RADIUS
request = client.create_auth_packet(User_Name="testuser")

# Mã hóa mật khẩu theo cơ chế PAP của RADIUS
request["User-Password"] = request.pw_crypt("TestPass123")

try:
    response = client.send_packet(request)

    if response is None:
        print("Không nhận được phản hồi RADIUS.")
    elif response.code == PacketType.AccessAccept:
        print("ACCESS ACCEPT: Xác thực thành công.")
    elif response.code == PacketType.AccessReject:
        print("ACCESS REJECT: Máy chủ từ chối xác thực.")
    else:
        print(f"Phản hồi RADIUS: {response.code}")

except TimeoutError:
    print("TIMEOUT: Không nhận được phản hồi từ FreeRADIUS.")
    print("Kiểm tra IP, UDP 1812, shared secret và log máy chủ.")
except Exception as exc:
    print(f"Lỗi khi gửi yêu cầu RADIUS: {type(exc).__name__}: {exc}")
