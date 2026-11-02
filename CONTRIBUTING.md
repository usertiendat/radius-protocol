# CONTRIBUTING.md

# QUY ĐỊNH ĐÓNG GÓP CODE — RADIUS PROTOCOL

Tài liệu này quy định quy trình phát triển, quản lý mã nguồn, dependencies, kiểm thử và tạo Pull Request cho dự án **RADIUS Protocol – Network Access Management**.

Mục tiêu:
- Đảm bảo code của các thành viên có thể chạy trên môi trường của nhau.
- Hạn chế lỗi phát sinh khi tích hợp code vào nhánh `main`.
- Thống nhất cách quản lý thư viện Python và môi trường phát triển.
- Đảm bảo mỗi chức năng đều có kiểm thử phù hợp.
- Giúp người review có thể cài đặt, chạy và đánh giá code một cách độc lập.

---

## 1. CÔNG NGHỆ SỬ DỤNG

Các thành viên thống nhất sử dụng những công nghệ chính sau:

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ Backend | Python 3.12.x |
| Backend Framework | FastAPI |
| ASGI Server | Uvicorn |
| RADIUS Server | FreeRADIUS 3.x |
| RADIUS Client | pyrad2 |
| Database | MariaDB |
| ORM | SQLAlchemy |
| Database Driver | PyMySQL |
| Kiểm thử | pytest |
| API Testing | FastAPI TestClient / HTTPX |
| Quản lý mã nguồn | Git và GitHub |
| Git GUI | GitHub Desktop |

Mọi thay đổi về công nghệ hoặc phiên bản thư viện quan trọng cần được trao đổi và thống nhất với nhóm trước khi áp dụng.

---

## 2. QUẢN LÝ BRANCH

Mỗi thành viên phải phát triển trên branch riêng, không commit trực tiếp lên `main`.

### 2.1. Các branch chính

| Branch | Người phụ trách | Vai trò |
|---|---|---|
| `main` | Tiến Đạt | Nhánh chính, chứa code đã được review |
| `tiendat` | Tiến Đạt | Phát triển chức năng cá nhân |
| `tutam` | Nguyễn Tự Tâm | Phát triển chức năng cá nhân |
| `khanhtrinh` | Lê Ngọc Khánh Trình | Phát triển chức năng cá nhân |

### 2.2. Quy định

1. Không phát triển trực tiếp trên `main`.
2. Mỗi thành viên chỉ commit công việc của mình lên branch tương ứng.
3. Không tự ý push code chưa hoàn thiện lên `main`.
4. Không tự ý merge Pull Request của chính mình.
5. Mọi thay đổi cần được gửi thông qua Pull Request.
6. Trước khi bắt đầu công việc mới, cần cập nhật branch từ phiên bản `main` mới nhất khi phù hợp.

### 2.3. Quy trình làm việc

```text
main
  |
  |--- tiendat
  |       |
  |       |--- Commit code
  |       |--- Push
  |       |--- Create Pull Request
  |       |
  |       └--- Review và Merge
  |
  |--- tutam
  |       |
  |       |--- Commit code
  |       |--- Push
  |       |--- Create Pull Request
  |       |
  |       └--- Review và Merge
  |
  └--- khanhtrinh
          |
          |--- Commit code
          |--- Push
          |--- Create Pull Request
          |
          └--- Review và Merge
```

---

## 3. QUẢN LÝ MÔI TRƯỜNG PYTHON

### 3.1. Phiên bản Python

Các thành viên thống nhất sử dụng Python 3.12.x để hạn chế khác biệt môi trường và tăng khả năng tương thích giữa các thư viện.

Không tự ý sử dụng phiên bản Python khác cho môi trường phát triển chính nếu chưa trao đổi với nhóm.

### 3.2. Tạo môi trường ảo

Mỗi thành viên phải tự tạo môi trường ảo trên máy của mình.

Tại thư mục gốc dự án, chạy:

```powershell
py -3.12 -m venv .venv
```

Kích hoạt môi trường ảo:

```powershell
.\.venv\Scripts\Activate.ps1
```

Kiểm tra phiên bản Python:

```powershell
python --version
```

### 3.3. Cài đặt dependencies

Cài đặt thư viện từ file requirements chung:

```powershell
python -m pip install -r requirements.txt
```

Nếu cần cài thêm các công cụ phục vụ phát triển và kiểm thử:

```powershell
python -m pip install -r requirements-dev.txt
```

Không yêu cầu thành viên gửi hoặc commit thư mục `.venv` của mình.

---

## 4. QUẢN LÝ DEPENDENCIES

### 4.1. File requirements.txt

Repository sử dụng file `requirements.txt` tại thư mục gốc để quản lý các thư viện cần thiết cho ứng dụng.

Ví dụ:

```text
fastapi
uvicorn
python-dotenv
pyrad2
SQLAlchemy
PyMySQL
```

Danh sách và phiên bản chính thức phải được kiểm tra, thống nhất và cập nhật theo dependencies thực tế của dự án.

### 4.2. File requirements-dev.txt

File `requirements-dev.txt` dùng để khai báo các thư viện phục vụ phát triển và kiểm thử.

Ví dụ:

```text
-r requirements.txt
pytest
httpx
```

### 4.3. Quy định khi thêm thư viện

Khi một thành viên sử dụng thư viện mới:

1. Kiểm tra thư viện đã tồn tại trong requirements hay chưa.
2. Nếu chưa có, bổ sung vào file requirements phù hợp.
3. Xác định phiên bản tương thích.
4. Kiểm tra lại chức năng sau khi cài đặt.
5. Commit file requirements cùng với code sử dụng thư viện đó.

Không được sử dụng thư viện bên ngoài mà không khai báo dependencies tương ứng.

Không tự ý thay đổi hoặc nâng cấp hàng loạt phiên bản thư viện nếu không có lý do kỹ thuật rõ ràng.

---

## 5. QUY ĐỊNH VIẾT TEST CASE

Mỗi thành viên có trách nhiệm viết test case cho chức năng mình phát triển.

Không được chỉ gửi code mà không có phương án kiểm thử.

### 5.1. Cấu trúc thư mục test

Các test case được tổ chức tập trung trong `backend/tests/`.

Cấu trúc tham khảo:

```text
backend/
├── app/
│   ├── main.py
│   ├── database.py
│   ├── radius_auth.py
│   ├── accounting.py
│   └── schemas.py
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_accounting.py
│   ├── test_database.py
│   └── test_integration.py
│
└── radius_dictionary
```

Tên file test phải bắt đầu bằng `test_`.

Tên hàm test phải bắt đầu bằng `test_`.

Ví dụ:

```python
def test_login_success():
    pass

def test_login_invalid_password():
    pass

def test_get_accounting_sessions():
    pass
```

### 5.2. Các trường hợp cần kiểm thử

Tùy chức năng, test case nên bao gồm:

- Trường hợp thành công.
- Trường hợp thất bại.
- Dữ liệu rỗng.
- Dữ liệu không hợp lệ.
- Giá trị biên.
- Lỗi kết nối hoặc lỗi phụ thuộc bên ngoài.
- Trường hợp liên quan đến bảo mật.

### 5.3. Phân loại kiểm thử

**Unit Test**

Kiểm tra từng hàm hoặc module riêng biệt.

- Không phụ thuộc vào FreeRADIUS đang chạy.
- Không phụ thuộc vào database thật.
- Sử dụng mock khi cần kiểm tra các thành phần bên ngoài.

**Integration Test**

Kiểm tra khả năng hoạt động giữa nhiều thành phần.

Ví dụ:
- FastAPI kết nối MariaDB.
- FastAPI gửi yêu cầu xác thực đến FreeRADIUS.
- FreeRADIUS ghi Accounting vào MariaDB.

Integration Test phải ghi rõ những dịch vụ cần khởi động và cấu hình cần có.

Không được để Unit Test phụ thuộc vào việc FreeRADIUS hoặc MariaDB đang chạy.

### 5.4. Chạy test

Tại thư mục gốc dự án:

```powershell
python -m pytest backend/tests -v
```

Nếu muốn chạy một file cụ thể:

```powershell
python -m pytest backend/tests/test_auth.py -v
```

Nếu muốn xem mức độ bao phủ kiểm thử, nhóm có thể bổ sung `pytest-cov` và thống nhất lệnh chạy riêng.

### 5.5. Yêu cầu trước khi tạo Pull Request

- Các Unit Test liên quan phải chạy thành công.
- Integration Test phải được chạy nếu chức năng có phụ thuộc bên ngoài.
- Không bỏ qua test đang thất bại mà không giải thích.
- Nếu chưa thể kiểm thử một trường hợp, phải ghi rõ lý do trong Pull Request.

---

## 6. QUẢN LÝ FILE CẤU HÌNH VÀ THÔNG TIN BÍ MẬT

### 6.1. File .env

Mỗi thành viên tự tạo file `.env` trên máy cá nhân.

Không được commit:
- Mật khẩu database thật.
- RADIUS shared secret thật.
- API key.
- Token xác thực.
- Thông tin đăng nhập cá nhân.

### 6.2. File .env.example

Repository phải có file `.env.example` để mô tả những biến môi trường cần thiết.

Ví dụ:

```env
RADIUS_SERVER=127.0.0.1
RADIUS_AUTH_PORT=1812
RADIUS_SECRET=CHANGE_ME

DATABASE_URL=mysql+pymysql://USER:PASSWORD@HOST:3306/radius_db
```

Đây chỉ là cấu hình mẫu. Mỗi thành viên phải sử dụng thông tin kết nối phù hợp với môi trường của mình.

Không được đưa shared secret hoặc mật khẩu thật vào `.env.example`.

### 6.3. File .gitignore

Các file và thư mục sau phải được loại khỏi Git:

```gitignore
.venv/
venv/
__pycache__/
*.py[cod]
.pytest_cache/
.env
```

Phải giữ lại `.env.example` để các thành viên khác có thể tham khảo cấu hình.

Không commit thư mục môi trường ảo, cache Python hoặc dữ liệu bí mật.

---

## 7. QUY ĐỊNH VIẾT CODE

1. Đặt tên biến, hàm và class có ý nghĩa.
2. Chia module theo chức năng, tránh viết toàn bộ logic trong một file.
3. Không lặp lại code không cần thiết.
4. Xử lý lỗi phù hợp, không để chương trình dừng đột ngột khi gặp lỗi có thể dự đoán.
5. Không trả về mật khẩu hoặc thông tin xác thực nhạy cảm trong API response.
6. Không ghi mật khẩu hoặc RADIUS shared secret vào log.
7. Không sử dụng dữ liệu đầu vào chưa kiểm soát trực tiếp trong câu lệnh SQL.
8. Các API phải có mã HTTP và cấu trúc response phù hợp.
9. Các chức năng có liên quan đến database phải quản lý vòng đời Session đúng cách.
10. Các thay đổi về cấu trúc database phải được thông báo và ghi lại để những thành viên khác có thể đồng bộ.

---

## 8. QUY ĐỊNH COMMIT

Commit message phải ngắn gọn, thể hiện rõ nội dung thay đổi.

Một số tiền tố khuyến nghị:

| Tiền tố | Ý nghĩa |
|---|---|
| `feat:` | Thêm chức năng |
| `fix:` | Sửa lỗi |
| `test:` | Thêm hoặc cập nhật test |
| `docs:` | Cập nhật tài liệu |
| `refactor:` | Tái cấu trúc code |
| `chore:` | Công việc cấu hình, bảo trì |

Ví dụ:

```text
feat: Add Accounting API
fix: Correct database session dependency
test: Add Accounting API unit tests
docs: Update backend setup instructions
chore: Update Python requirements
```

Không commit file không liên quan đến chức năng đang phát triển.

---

## 9. QUY ĐỊNH TẠO PULL REQUEST

Trước khi tạo Pull Request, thành viên cần:

1. Kiểm tra branch đang làm việc.
2. Kiểm tra code đã được lưu và commit đầy đủ.
3. Cập nhật requirements nếu có sử dụng thư viện mới.
4. Viết và chạy test case.
5. Kiểm tra không commit `.env`, `.venv` hoặc thông tin bí mật.
6. Push code lên branch cá nhân.
7. Tạo Pull Request từ branch cá nhân vào `main`.

### 9.1. Nội dung Pull Request

Mỗi Pull Request cần có:

- Mục đích thay đổi.
- Những chức năng đã triển khai.
- Danh sách file quan trọng đã thay đổi.
- Dependencies mới (nếu có).
- Test case đã thực hiện.
- Kết quả kiểm thử.
- Cấu hình hoặc dịch vụ cần thiết để chạy thử.
- Những vấn đề còn tồn tại hoặc chưa hoàn thiện.

### 9.2. Checklist trước khi gửi PR

Thành viên cần tự kiểm tra:

- [ ] Code đã hoàn thiện theo phạm vi công việc.
- [ ] Không commit trực tiếp lên `main`.
- [ ] Đã cập nhật requirements nếu sử dụng thư viện mới.
- [ ] Đã viết test case phù hợp.
- [ ] Unit Test đã chạy thành công.
- [ ] Đã kiểm tra Integration Test nếu cần.
- [ ] Đã cập nhật README hoặc tài liệu liên quan.
- [ ] Không commit `.env`, `.venv`, cache hoặc thông tin bí mật.
- [ ] Đã ghi rõ cách chạy và kiểm thử chức năng.

---

## 10. QUY TRÌNH REVIEW VÀ MERGE

Người phụ trách review sẽ:

1. Kiểm tra nội dung và phạm vi thay đổi của PR.
2. Kiểm tra cấu trúc code.
3. Kiểm tra dependencies.
4. Cài đặt và chạy test trên môi trường độc lập.
5. Kiểm thử chức năng thực tế nếu cần.
6. Kiểm tra các vấn đề bảo mật.
7. Yêu cầu thành viên sửa nếu phát hiện lỗi.
8. Chỉ approve và merge khi các yêu cầu bắt buộc đã được đáp ứng.

### Các trường hợp chưa được merge

- Có lỗi nghiêm trọng trong code.
- Test case bắt buộc thất bại.
- Thiếu dependencies khiến người khác không thể chạy code.
- Có nguy cơ lộ mật khẩu hoặc thông tin bí mật.
- Có merge conflict chưa được giải quyết.
- Chưa có hướng dẫn cấu hình hoặc kiểm thử cần thiết.

Người viết code có trách nhiệm sửa lỗi và push commit mới lên chính branch đã tạo Pull Request.

Không cần tạo Pull Request mới khi chỉ cập nhật code trong cùng một phạm vi công việc.

---

## 11. NGUYÊN TẮC CHUNG

- Mỗi thành viên chịu trách nhiệm về chất lượng code mình đóng góp.
- Không xem việc code chạy trên máy cá nhân là bằng chứng code đã hoạt động đúng trên môi trường chung.
- Không tự ý thay đổi cấu trúc hoặc công nghệ quan trọng mà chưa trao đổi với nhóm.
- Ưu tiên code rõ ràng, dễ kiểm thử và dễ bảo trì.
- Ưu tiên an toàn thông tin trong mọi chức năng liên quan đến xác thực và quản lý truy cập mạng.
- Mọi thay đổi quan trọng phải được ghi nhận thông qua Git và Pull Request.

**Nguyên tắc cuối cùng: Code chỉ được xem là sẵn sàng tích hợp khi có thể cài đặt, chạy và kiểm thử trên môi trường của một thành viên khác.**