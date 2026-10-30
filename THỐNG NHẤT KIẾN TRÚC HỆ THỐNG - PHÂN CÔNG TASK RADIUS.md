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

### 9. Trạng thái hiện tại

Đã hoàn thành:
- Khởi tạo FastAPI Backend.
- Xây dựng Authentication API.
- Cài đặt FreeRADIUS 3.2.8 trên WSL2.
- Cài đặt và kết nối MariaDB.
- Import schema FreeRADIUS.
- Kết nối FreeRADIUS SQL module với MariaDB.
- Xác thực tài khoản sqltest từ radcheck thành công.
- Ghi nhận Access-Accept trong radpostauth.
- Bật yêu cầu Message-Authenticator cho các RADIUS client đã cấu hình.

Đang triển khai:
- Hoàn thiện RADIUS Accounting.
- Kiểm tra Accounting-Start, Interim-Update và Accounting-Stop.
- Kiểm tra dữ liệu trong radacct.

Chưa triển khai:
- CRUD User/Group/NAS API.
- Dashboard Frontend.
- Admin Authentication.
- Thống kê và giám sát tổng thể.

**Đề nghị cả ba thành viên xác nhận tài liệu này trước khi triển khai các module tiếp theo. Mọi thay đổi về công nghệ, database schema hoặc API contract cần được thống nhất trong nhóm trước khi thực hiện.**