# THỐNG NHẤT KIẾN TRÚC VÀ PHÂN CHIA MODULE
## Dự án: RADIUS Management System

### 1. Mục tiêu dự án

Xây dựng hệ thống quản lý và giám sát xác thực RADIUS, sử dụng FreeRADIUS làm máy chủ AAA, FastAPI làm Backend trung tâm, React làm giao diện quản trị và MariaDB làm cơ sở dữ liệu.

Các chức năng chính:
- Quản lý người dùng RADIUS.
- Xác thực người dùng thông qua FreeRADIUS.
- Quản lý nhóm và thuộc tính phân quyền.
- Ghi nhận lịch sử phiên sử dụng bằng RADIUS Accounting.
- Theo dõi lịch sử xác thực thành công/thất bại.
- Dashboard thống kê và giám sát hệ thống.
- Quản lý tài khoản Admin.

### 2. Công nghệ thống nhất

| Thành phần | Công nghệ |
|---|---|
| Frontend | React + Vite + TypeScript |
| Backend | Python + FastAPI |
| API | RESTful API, HTTP, JSON |
| Database | MariaDB 10.4.x |
| ORM | SQLAlchemy 2.x |
| Validation | Pydantic |
| Database Driver | PyMySQL |
| RADIUS Server | FreeRADIUS 3.2.x |
| Python RADIUS Client | pyrad2 |
| Authentication | RADIUS PAP trong phạm vi MVP |
| RADIUS Authentication Port | UDP 1812 |
| RADIUS Accounting Port | UDP 1813 |
| Testing | pytest, Postman, radtest, radclient |
| Version Control | Git + GitHub |
| Environment | Windows + XAMPP + Ubuntu WSL2 |

Không tự ý đổi framework hoặc công nghệ chính nếu chưa được cả nhóm thống nhất.

### 3. Kiến trúc hệ thống

Luồng tổng quát:

React Frontend
→ FastAPI Backend
→ FreeRADIUS
→ MariaDB

Các luồng riêng:

**Admin Authentication**
- Admin đăng nhập Dashboard thông qua FastAPI.
- FastAPI kiểm tra tài khoản trong bảng app_admins.
- Đây là tài khoản quản trị ứng dụng, không phải RADIUS User.

**RADIUS Authentication**
- React gửi yêu cầu đến FastAPI.
- FastAPI sử dụng pyrad2 gửi Access-Request đến FreeRADIUS qua UDP 1812.
- FreeRADIUS sử dụng SQL module truy vấn MariaDB.
- FreeRADIUS trả Access-Accept hoặc Access-Reject.

**RADIUS Accounting**
- NAS/RADIUS Client gửi Accounting-Request đến FreeRADIUS qua UDP 1813.
- FreeRADIUS xử lý Accounting và ghi dữ liệu vào radacct.
- FastAPI đọc dữ liệu để cung cấp cho Dashboard.

### 4. Cấu trúc dữ liệu

Database sử dụng tên radius_db.

**Nhóm bảng quản trị ứng dụng:**
- app_admins: Tài khoản quản trị Dashboard.
- app_settings: Cấu hình ứng dụng nếu cần.

**Nhóm bảng RADIUS chuẩn FreeRADIUS:**
- radcheck: Thuộc tính xác thực người dùng.
- radreply: Thuộc tính trả về người dùng.
- radusergroup: Gán người dùng vào nhóm.
- radgroupcheck: Điều kiện xác thực của nhóm.
- radgroupreply: Thuộc tính trả về của nhóm.
- radacct: Lịch sử phiên Accounting.
- radpostauth: Lịch sử kết quả xác thực.
- nas: Danh sách thiết bị NAS.
- nasreload: Theo dõi yêu cầu reload NAS.

Không tự ý đổi tên bảng hoặc cột chuẩn FreeRADIUS.

**Nguyên tắc dữ liệu:**
- FreeRADIUS sử dụng trực tiếp các bảng RADIUS chuẩn.
- FastAPI sử dụng SQLAlchemy để quản lý và truy vấn dữ liệu.
- Không tạo một bảng users riêng để lưu mật khẩu RADIUS gây trùng lặp dữ liệu.
- Mật khẩu Admin phải được hash.
- Không lưu plaintext password hoặc shared secret trong log.
- Không commit dữ liệu chứa mật khẩu hoặc secret lên GitHub.

### 5. API contract đề xuất

Prefix API mới: /api/v1

| Module | Method | Endpoint |
|---|---|---|
| Health | GET | /health |
| Admin Auth | POST | /api/v1/auth/login |
| Admin Auth | GET | /api/v1/auth/me |
| RADIUS Auth | POST | /api/v1/radius/authenticate |
| User | GET | /api/v1/users |
| User | GET | /api/v1/users/{username} |
| User | POST | /api/v1/users |
| User | PUT | /api/v1/users/{username} |
| User | DELETE | /api/v1/users/{username} |
| Group | GET | /api/v1/groups |
| Group | POST | /api/v1/groups |
| Group | PUT | /api/v1/groups/{groupname} |
| Group | DELETE | /api/v1/groups/{groupname} |
| Accounting | GET | /api/v1/accounting/sessions |
| Accounting | GET | /api/v1/accounting/sessions/{id} |
| Accounting | GET | /api/v1/accounting/statistics |
| Logs | GET | /api/v1/logs/authentication |
| Dashboard | GET | /api/v1/dashboard/summary |
| NAS | GET | /api/v1/nas |
| NAS | POST | /api/v1/nas |

Lưu ý: Đây là API contract mục tiêu. Các endpoint chưa được triển khai sẽ được phát triển theo hợp đồng này.

Endpoint POST /auth/login hiện tại của Backend Authentication cần được giữ tương thích trong quá trình chuyển đổi; không tự ý xóa hoặc đổi endpoint đang hoạt động.

### 6. Phân chia công việc

**Nguyễn Tiến Đạt – FreeRADIUS, Authentication và Backend Core**
- Cấu hình và quản lý FreeRADIUS.
- Cấu hình RADIUS SQL module.
- Xây dựng và duy trì Authentication API.
- Tích hợp FastAPI với FreeRADIUS bằng pyrad2.
- Kiểm thử Authentication và hỗ trợ tích hợp hệ thống.

**Nguyễn Tự Tâm – Database và User Management**
- Thiết kế SQLAlchemy models.
- Xây dựng API quản lý RADIUS User.
- Xây dựng API quản lý Group.
- Xây dựng API quản lý NAS.
- Xử lý CRUD, transaction và quan hệ dữ liệu.

**Lê Ngọc Khánh Trình – Accounting, Frontend và Dashboard**
- Cấu hình và kiểm thử RADIUS Accounting.
- Xây dựng API truy vấn Accounting.
- Xây dựng React + TypeScript Dashboard.
- Hiển thị lịch sử xác thực và phiên sử dụng.
- Tích hợp Frontend với Backend API.

**Cả nhóm cùng thực hiện:**
- Thống nhất API contract.
- Kiểm thử tích hợp.
- Review Pull Request.
- Viết tài liệu, báo cáo và chuẩn bị demo.

### 7. Quy ước Git

Repository: usertiendat/radius-protocol

Các branch:
- main: Nhánh ổn định.
- tiendat: Nguyễn Tiến Đạt.
- tutam: Nguyễn Tự Tâm.
- khanhtrinh: Lê Ngọc Khánh Trình.

Quy trình:
1. Mỗi thành viên làm việc trên branch riêng.
2. Commit theo chức năng.
3. Push branch lên GitHub.
4. Tạo Pull Request vào main.
5. Thành viên phụ trách review trước khi merge.
6. Không tự ý push trực tiếp lên main.

### 8. Quy tắc phối hợp

- Không tự ý sửa schema database đã thống nhất.
- Không tự ý đổi tên API hoặc cấu trúc JSON.
- Nếu cần thay đổi API, phải thông báo cho thành viên phụ trách module liên quan.
- Không sửa file của thành viên khác nếu chưa trao đổi.
- Các thay đổi lớn phải được kiểm thử trước khi tạo Pull Request.
- Không commit .env, .venv, mật khẩu, shared secret hoặc dữ liệu nhạy cảm.

### 9. Trạng thái hiện tại (Cập nhật ngày 16/11/2026)

**Đã hoàn thành:**
- **Nguyễn Tiến Đạt (Core, Database, Security & Admin Auth):**
  - Khởi tạo kiến trúc FastAPI Backend, quản lý cấu hình tập trung (`app/core/config.py`).
  - Thiết kế đầy đủ SQLAlchemy ORM Models: 9 bảng chuẩn FreeRADIUS (`radcheck`, `radreply`, `radacct`, `nas`,...) và 2 bảng ứng dụng (`app_admins`, `app_users`), kèm công cụ kiểm tra tính toàn vẹn Schema Verifier.
  - Quản lý vòng đời kết nối CSDL và Session connection pool trong `app/database.py`.
  - Triển khai Service Layer nền tảng (`BaseService`) và cơ chế quản lý giao dịch tường minh `transactional()`.
  - Triển khai Global Exception Handling và chuẩn hóa ánh xạ mã lỗi HTTP (`app/core/exception_handlers.py`).
  - Xây dựng Health Monitoring Router (`/health` và `/health/database`).
  - Cài đặt và cấu hình FreeRADIUS 3.2.x trên WSL2 kết nối MariaDB; tích hợp xác thực RADIUS PAP qua `pyrad2` (`app/radius_auth.py`).
  - Xây dựng hoàn chỉnh phân hệ Admin Authentication & Security (Phase 0B):
    - Dịch vụ xác thực Admin (`AdminAuthService`) với cơ chế băm mật khẩu bảo mật cao PBKDF2-HMAC-SHA256 (310.000 vòng) và chống timing attack.
    - Dịch vụ JWT Token (`AdminTokenService`) hỗ trợ phát hành Access Token chuẩn OAuth2 Bearer, kiểm tra tính toàn vẹn và hết hạn.
    - Phân quyền RBAC (`AdminRole`, `require_roles`) và Dependency tiêm danh tính quản trị viên `get_current_admin`.
    - API Đăng nhập Admin: `POST /api/v1/admin/auth/login`.
    - API Lấy thông tin Admin hiện tại: `GET /api/v1/admin/auth/me`.
    - API Đổi mật khẩu an toàn: `POST /api/v1/admin/auth/change-password` (chống IDOR, kiểm tra mật khẩu hiện tại, cấm trùng mật khẩu cũ, phân tách Session với `use_cache=False`).
    - Hoàn thành bộ kiểm thử hồi quy nền tảng Foundation Regression Suite gồm 15 file test với 266 test cases đạt tỷ lệ Pass 100%.
    - Chuẩn hóa toàn bộ Tài liệu kiến trúc kỹ thuật Backend (`backend/ARCHITECTURE.md`) phiên bản 1.9.0.
- **Nguyễn Tự Tâm (Quản lý User, Group, NAS - Nhánh `tutam`):**
  - Đã hoàn thành Pydantic Schemas, Service Layer và API Router CRUD cho User (`/api/v1/users`), Group (`/api/v1/groups`) và NAS (`/api/v1/nas`).
  - Viết bộ Unit Test cho `UserService` và `NASService`.
- **Lê Ngọc Khánh Trình (Accounting & Dashboard - Nhánh `khanhtrinh`):**
  - Đã hoàn thành API Router cho Accounting (`/api/v1/accounting/sessions`, `/statistics`, `/session-trend`, `/logs/authentication`, `/dashboard/summary`).
  - Xây dựng giao diện Dashboard giám sát HTML/CSS/JS (`backend/app/static/dashboard.html`) kết nối fetch dữ liệu trực tiếp theo thời gian thực và tự động làm mới.

**Đang triển khai:**
- Review code và tạo Pull Request để hợp nhất (Merge) các nhánh `tiendat`, `tutam`, `khanhtrinh` vào nhánh `main`.
- Giải quyết xung đột cấu hình router tổng tại `backend/app/main.py`.
- Tích hợp Dependency bảo vệ Bearer Token JWT (`get_current_admin`) vào các router User, Group, NAS và Accounting.

**Kế hoạch tiếp theo:**
- Kiểm thử tích hợp toàn diện hệ thống (End-to-End Testing): Tạo User -> Xác thực qua FreeRADIUS -> Ghi nhận phiên Accounting -> Giám sát trên Dashboard.
- Triển khai môi trường Docker Compose chứa MariaDB và FreeRADIUS cô lập để chạy kiểm thử staging.


**Đề nghị cả ba thành viên xác nhận tài liệu này trước khi triển khai các module tiếp theo. Mọi thay đổi về công nghệ, database schema hoặc API contract cần được thống nhất trong nhóm trước khi thực hiện.**