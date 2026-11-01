# RADIUS Enterprise Authentication & Access Control

Xây dựng hệ thống xác thực người dùng và kiểm soát quyền truy cập mạng trong môi trường doanh nghiệp sử dụng giao thức RADIUS.

## 1. Mô tả chi tiết

### Giới thiệu

**RADIUS Enterprise Authentication & Access Control** là một project nghiên cứu và xây dựng hệ thống xác thực tập trung dựa trên giao thức **RADIUS (Remote Authentication Dial-In User Service)**.

Dự án mô phỏng cách RADIUS được sử dụng trong môi trường doanh nghiệp để xác thực người dùng khi truy cập các tài nguyên mạng như **Wi-Fi, VPN hoặc Network Access Server (NAS)**.

Project được xây dựng nhằm tìm hiểu cơ chế **AAA (Authentication, Authorization, Accounting)** và đánh giá khả năng ứng dụng của RADIUS trong việc quản lý truy cập mạng tập trung.

### Công nghệ sử dụng

* **RADIUS / FreeRADIUS** – Xử lý xác thực và quản lý truy cập mạng.
* **Python** – Xây dựng các thành phần hỗ trợ và xử lý logic của hệ thống.
* **FastAPI** – Xây dựng REST API.
* **MySQL / MariaDB** – Lưu trữ thông tin người dùng, chính sách và log.
* **HTML / CSS / JavaScript / Bootstrap** – Xây dựng giao diện quản trị.
* **Linux** – Môi trường triển khai RADIUS Server.
* **VMware** – Xây dựng môi trường mạng ảo để mô phỏng hệ thống doanh nghiệp.
* **Wireshark** – Phân tích và kiểm tra RADIUS traffic.

### Chức năng chính

#### Authentication

Xác thực người dùng thông qua RADIUS Server.

```text
Client
   |
   | Access-Request
   ↓
RADIUS Server
   |
   ├── Access-Accept
   └── Access-Reject
```

#### Authorization

Quản lý quyền truy cập dựa trên nhóm hoặc vai trò của người dùng.

Ví dụ:

```text
Admin       → Full Access
IT Staff    → Internal Network
Employee    → Business Network
Guest       → Limited Access
```

#### Accounting

Ghi nhận thông tin liên quan đến các phiên truy cập mạng và hoạt động xác thực.

#### User Management

* Quản lý tài khoản người dùng.
* Thêm, sửa, xóa người dùng.
* Khóa hoặc mở khóa tài khoản.
* Phân nhóm người dùng.
* Quản lý quyền truy cập.

#### Authentication Monitoring

Theo dõi các lần xác thực thành công và thất bại.

Ví dụ:

```text
Successful Authentication
Failed Authentication
Account Locked
Suspicious Login
```

### Mục tiêu dự án

Dự án hướng tới việc xây dựng một mô hình có thể mô phỏng:

```text
Authentication
      ↓
Authorization
      ↓
Accounting
      ↓
Access Control
      ↓
Monitoring
```

Qua đó nghiên cứu cách một hệ thống xác thực tập trung có thể hỗ trợ việc quản lý người dùng và kiểm soát truy cập mạng trong doanh nghiệp.

---

## 2. Hướng dẫn cài đặt (Installation)

### Yêu cầu hệ thống

* Windows / Linux
* VMware Workstation hoặc phần mềm máy ảo tương đương
* Linux VM
* Python 3.10+
* MySQL hoặc MariaDB
* FreeRADIUS
* Git

### Bước 1: Clone repository

```bash
git clone https://github.com/usertiendat/radius-protocol.git
cd radius-protocol
```


### Bước 2: Cài đặt FreeRADIUS

Trên Ubuntu/Debian:

```bash
sudo apt update
sudo apt install freeradius freeradius-mysql
```

Kiểm tra:

```bash
radiusd -v
```

Hoặc:

```bash
freeradius -v
```

### Bước 3: Cấu hình RADIUS Server

Cấu hình RADIUS Server theo môi trường lab.

Các thành phần cần cấu hình bao gồm:

* RADIUS Client
* Shared Secret
* Authentication
* Database
* User/Group
* Access Policy

Sau khi cấu hình, kiểm tra server:

```bash
sudo freeradius -X
```

### Bước 4: Cài đặt Backend

Di chuyển vào thư mục backend:

```bash
cd backend
```

Tạo virtual environment:

```bash
python -m venv venv
```

Kích hoạt:

**Windows:**

```bash
venv\Scripts\activate
```

**Linux:**

```bash
source venv/bin/activate
```

Cài đặt thư viện:

```bash
pip install -r requirements.txt
```

### Bước 5: Cấu hình Database

Backend dùng SQLite tại `backend/radius.db` nếu chưa cấu hình database. Để kết nối
MySQL/MariaDB, tạo file `.env` ở thư mục gốc dự án và khai báo:

```env
DB_HOST=localhost
DB_PORT=3306
DB_NAME=radius_db
DB_USER=root
DB_PASSWORD=your_password
```

Có thể dùng URL kết nối đầy đủ qua `DATABASE_URL` thay cho các biến `DB_*`.
Khi dùng MySQL/MariaDB, tạo database trước khi chạy backend:

```sql
CREATE DATABASE radius_db;
```

Các bảng được tạo tự động khi backend khởi động.

### Bước 6: Khởi động Backend

Từ thư mục `backend`:

```bash
uvicorn app.main:app --reload
```

Tài liệu Swagger: `http://127.0.0.1:8000/docs`.

#### API quản lý

| Tài nguyên | Endpoint |
|---|---|
| User | `GET/POST /users`, `GET/PATCH/DELETE /users/{user_id}` |
| Group | `GET/POST /groups`, `GET/PATCH/DELETE /groups/{group_id}` |
| NAS | `GET/POST /nas`, `GET/PATCH/DELETE /nas/{nas_id}` |

Tạo user nhận `username`, `password` và tùy chọn `group_ids`. Password được
PBKDF2 hash trước khi lưu. User có thể thuộc nhiều group; xóa user hoặc group
sẽ xóa các liên kết tương ứng. NAS nhận `name`, `ip_address`, `shared_secret`
và tùy chọn `description`, `is_active`. API không trả password hash hoặc NAS
shared secret trong response.

> API quản trị hiện chưa có cơ chế xác thực/ủy quyền. Chỉ nên chạy trong môi
> trường phát triển tin cậy; cần bổ sung bảo vệ truy cập và HTTPS trước khi
> triển khai thực tế.

---

## 3. Cách sử dụng (Usage)

### Khởi động RADIUS Server

```bash
sudo freeradius -X
```

RADIUS Server sẽ chạy ở chế độ debug để hiển thị quá trình xử lý request.

### Khởi động Backend

Chạy tại thư mục `backend`:

```bash
uvicorn app.main:app --reload
```

### Kiểm tra RADIUS Authentication

Có thể sử dụng RADIUS client để gửi authentication request đến RADIUS Server.

Ví dụ:

```bash
radtest username password localhost 0 testing123
```

Nếu thông tin xác thực hợp lệ:

```text
Access-Accept
```

Nếu không hợp lệ:

```text
Access-Reject
```

### Kiểm tra RADIUS Traffic bằng Wireshark

Có thể sử dụng Wireshark để quan sát quá trình:

```text
Access-Request
      ↓
RADIUS Server
      ↓
Access-Accept / Access-Reject
```

Việc phân tích packet giúp kiểm tra quá trình trao đổi giữa RADIUS Client và RADIUS Server trong môi trường lab.

---

## 4. Thông tin khác

### Thành viên

- **Nguyễn Tiến Đạt** – Project Lead / Developer
- **Nguyễn Tự Tâm** – Contributor / Support
- **Lê Ngọc Khánh Trình** – Contributor / Support

### Tính năng dự kiến

Các chức năng dự kiến được triển khai trong project:

* [ ] Web Dashboard
* [x] User Management API
* [x] Group Management API
* [ ] Authentication Log
* [ ] Accounting
* [ ] Access Control Policy
* [ ] Brute-force Detection
* [ ] Account Locking
* [ ] Security Alert
* [ ] RADIUS + Enterprise Wi-Fi Simulation
* [ ] RADIUS + VPN Simulation
* [ ] Monitoring và thống kê hệ thống

### Mục đích

Dự án được thực hiện với mục đích **học tập, nghiên cứu giao thức RADIUS và mô phỏng hệ thống xác thực mạng trong môi trường doanh nghiệp**.

### License

This project is for educational and research purposes.
