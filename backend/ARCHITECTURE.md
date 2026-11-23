# TÀI LIỆU KIẾN TRÚC BACKEND (ARCHITECTURE CONTRACT)
## RADIUS Enterprise Authentication & Access Control System

> **Phiên bản tài liệu**: 1.9.0 — Phase 0B Step 1.3 (Foundation Final Architecture & Documentation)  
> **Cập nhật ngày**: 16/11/2026  
> **Trạng thái**: Foundation Architecture Accepted; Foundation Security Audit – Conditional Pass; Release 1 Deployment Gates Pending.

---

## 1. TỔNG QUAN KIẾN TRÚC PHÂN LỚP (LAYERED ARCHITECTURE)

Hệ thống Backend được xây dựng trên nền tảng **FastAPI** kết hợp **SQLAlchemy 2.x ORM** và **FreeRADIUS 3.x / MariaDB**. Cấu trúc thư mục tuân thủ nghiêm ngặt mô hình phân tầng trách nhiệm (Separation of Concerns), bao gồm 27 physical Python source files trong package `backend/app/` và 15 test files thuộc Foundation Regression Suite:

```
backend/
├── app/
│   ├── core/                  # Cấu hình tập trung, bảo mật và dependencies nền tảng (8 files)
│   │   ├── __init__.py        # Re-export các thành phần quản trị (CurrentAdmin, RBAC)
│   │   ├── config.py          # Pydantic BaseSettings, nạp .env, che giấu secrets trong __repr__
│   │   ├── security.py        # PBKDF2-HMAC-SHA256 (310k vòng), hmac digest, PyJWT (HS256)
│   │   ├── dependencies.py    # Database Session lifecycle, DB health check, error sanitizer
│   │   ├── admin_dependencies.py # Current Admin Dependency (get_current_admin, HTTPBearer)
│   │   ├── rbac.py            # RBAC Foundation (AdminRole, require_roles dependency factory)
│   │   ├── exceptions.py      # Business Exception Contract (BaseBusinessException, NotFoundError,...)
│   │   └── exception_handlers.py # Global Exception Handlers & HTTP Error Mapping
│   ├── models/                # SQLAlchemy ORM Models & Schema Protection (4 files)
│   │   ├── __init__.py        # Re-export toàn bộ models và Schema Verifier
│   │   ├── radius.py          # 9 bảng chuẩn FreeRADIUS (radcheck, radacct, nas, ...)
│   │   ├── application.py     # 2 bảng quản trị ứng dụng (app_admins, app_users)
│   │   └── verifier.py        # Read-only Schema Verifier (tương thích MariaDB & SQLite)
│   ├── schemas/               # Pydantic Request Validation & Response Serialization (2 files)
│   │   ├── __init__.py        # Re-export và dynamic loader cho schemas kế thừa
│   │   ├── admin_auth.py      # Schemas: Login, Info, ChangePassword (Request & Response)
│   │   └── (tương lai)        # Schemas cho User, Group, Accounting
│   ├── services/              # Pure Business Logic Layer (độc lập với HTTP transport) (5 files)
│   │   ├── __init__.py        # Service Layer Contract & Re-exports
│   │   ├── base.py            # BaseService nhận Session qua DI
│   │   ├── transaction.py     # Transaction guard (Explicit Top-level Transaction Ownership)
│   │   ├── admin_auth.py      # AdminAuthService cho Dashboard Admin (PBKDF2, ChangePassword)
│   │   ├── admin_token.py     # AdminTokenService phát hành & kiểm định JWT Access Token (HS256, 30m)
│   │   └── (tương lai)        # UserService, GroupService, NasService
│   ├── routers/               # API Endpoints & HTTP Request/Response mapping (3 files)
│   │   ├── __init__.py        # Re-export API Routers
│   │   ├── health.py          # GET /health, GET /health/database
│   │   ├── admin_auth.py      # POST /login, GET /me, POST /change-password
│   │   └── (tương lai)        # users.py, groups.py, accounting.py
│   ├── database.py            # SQLAlchemy Engine singleton, SessionLocal, get_db()
│   ├── main.py                # FastAPI Application instance & router/handler registration
│   ├── radius_auth.py         # Module xác thực trực tiếp FreeRADIUS (PAP qua pyrad2)
│   ├── schemas.py             # Schema kế thừa từ Phase 0A (LoginRequest, LoginResponse)
│   └── __init__.py            # Root package initialization
├── test_core_security.py                      # Unit tests nhóm Core & Security (12 tests)
├── test_database_foundation.py                # Unit tests nhóm Database Engine & ORM (27 tests)
├── test_app_health.py                         # Unit tests nhóm Health Monitoring (9 tests)
├── test_service_foundation.py                 # Unit tests nhóm Service Layer & Transaction Safety (15 tests)
├── test_exception_handlers.py                 # Unit tests nhóm Global Exception Handlers (14 tests)
├── test_admin_auth.py                         # Unit tests nhóm Admin Authentication Service (15 tests)
├── test_admin_token.py                        # Unit tests nhóm Admin Token Service (22 tests)
├── test_admin_dependencies.py                 # Unit tests nhóm Current Admin Dependency (23 tests)
├── test_rbac.py                               # Unit tests nhóm RBAC Foundation (17 tests)
├── test_admin_login_api.py                    # Unit tests nhóm Admin Authentication API (18 tests)
├── test_admin_me_api.py                       # Unit tests: Handlers, Route Registration & Dependencies (16 tests)
├── test_admin_me_http_integration.py          # HTTP Integration tests qua FastAPI ASGI pipeline (12 tests)
├── test_admin_change_password_service.py      # Unit tests Admin Password Change Service Layer (18 tests)
├── test_admin_change_password_api.py          # Unit tests Admin Password Change API Handler & Schemas (16 tests)
└── test_admin_change_password_http_integration.py # HTTP Integration tests Admin Password Change qua ASGI (32 tests)
```

---

## 2. PHÂN ĐỊNH TRÁCH NHIỆM TỪNG TẦNG

| Phân tầng | Trách nhiệm chính | Trạng thái hiện tại |
| :--- | :--- | :---: |
| **Core** (`app/core/`) | Nạp biến môi trường an toàn, băm mật khẩu PBKDF2, phát hành/giải mã JWT token, kiểm tra kết nối CSDL, lọc bỏ secret khỏi log lỗi, phân quyền RBAC. | **Đã triển khai & nghiệm thu** |
| **Models** (`app/models/`) | Khai báo cấu trúc bảng CSDL (9 bảng FreeRADIUS + 2 bảng App), ràng buộc khóa chính, unique, index. Kiểm định toàn vẹn schema ở chế độ Read-Only. | **Đã triển khai & nghiệm thu** |
| **Routers** (`app/routers/`) | Nhận HTTP request, điều phối dependency injection (`get_db`), gọi Service tương ứng, ánh xạ exception thành HTTP status code. | **Đã triển khai health.py & admin_auth.py**; Routers nghiệp vụ mở rộng là định hướng Phase 1 |
| **Services** (`app/services/`) | Xử lý logic nghiệp vụ, kiểm tra quy tắc kinh doanh, thực hiện thao tác ORM qua `Session` được tiêm từ router, phân định transaction. | **Đã triển khai AdminAuthService & AdminTokenService**; Implementation mở rộng là định hướng Phase 1 |
| **Schemas** (`app/schemas/`) | Định nghĩa DTOs bằng Pydantic: kiểm tra tính hợp lệ dữ liệu đầu vào (validation), định dạng dữ liệu đầu ra, che giấu các trường nhạy cảm. | **Đã triển khai schemas Admin Auth & Change Password**; Schemas mở rộng là định hướng Phase 1 |

---

## 3. LUỒNG XỬ LÝ DỮ LIỆU CHUẨN (REQUEST-RESPONSE FLOW)

```
[ Client / Frontend ]
         │  (HTTP Request JSON + Authorization Header)
         ▼
[ FastAPI Router ] (app/routers/)
  ├── 1. Pydantic validate request body (app/schemas/)
  ├── 2. Xác thực JWT & inject CurrentAdmin qua get_current_admin (app/core/)
  ├── 3. Nhận Session qua Dependency Injection (Depends(get_db))
  ├── 4. Gọi Service function và truyền session: service.do_action(db, data)
  │        │
  │        ▼
  │   [ Service Layer ] (app/services/)
  │     ├── 5. Thực thi Business Rules & kiểm tra điều kiện an toàn
  │     ├── 6. Truy vấn / Ghi dữ liệu qua ORM Models (app/models/)
  │     ├── 7. Quản lý Transaction: with transactional(db): commit / rollback
  │     └── 8. Trả về Domain Object / DTO an toàn (hoặc ném Business Exception)
  │        │
  │        ▲
  ├── 9. Bắt Business Exception và chuyển thành JSON Response chuẩn qua Global Handlers
  └── 10. Định dạng Response DTO an toàn qua Schema (loại trừ password hash)
         │  (HTTP Response JSON)
         ▼
[ Client / Frontend ]
```

---

## 4. QUY TẮC DEPENDENCY INJECTION & SESSION LIFECYCLE

1. **Session per-request**: Mỗi request HTTP khởi tạo session độc lập thông qua generator `get_db()` (`SessionLocal()`).
2. **Tái sử dụng Engine Singleton**: Tất cả các session liên kết với singleton `engine` trong `app/database.py` (`pool_size=10`, `max_overflow=20`, `pool_recycle=3600`, `pool_pre_ping=True`).
3. **Đóng Session trong `finally`**: Khối `finally: db.close()` trong `get_db()` cung cấp cơ chế đóng session tiêu chuẩn trong phạm vi vòng đời request của FastAPI, hoàn trả kết nối về pool.
4. **Tự động Rollback khi Exception**: Nếu có ngoại lệ phát sinh chưa xử lý trong request, `get_db()` gọi `db.rollback()` trước khi đóng session để bảo vệ toàn vẹn dữ liệu.
5. **Import hoàn toàn Lazy**: Quá trình import module (`database.py`, `dependencies.py`, `main.py`) không mở socket kết nối tới MariaDB.

---

## 5. QUY TẮC QUẢN LÝ GIAO DỊCH (TRANSACTION OWNERSHIP)

Hệ thống áp dụng mô hình **Explicit Top-level Transaction Ownership** (Quyền sở hữu giao dịch tường minh ở cấp cao nhất):

1. **Chỉ Service cấp cao nhất (Top-level Service) quản lý Transaction**:
   - Quyền khởi tạo, commit hoặc rollback transaction thuộc về Service cấp cao nhất (entry-point service được gọi trực tiếp từ Router).
   - Router hoặc ORM Models không tự ý can thiệp vào transaction lifecycle.

2. **Service con (Child Services / Helper Services) không tự ý commit/rollback**:
   - Khi một Service gọi các Service con hoặc Helper functions, session được truyền xuyên suốt qua tham số `db: Session`.
   - Các Service con không gọi `db.commit()`, `db.rollback()` hoặc bọc trong context manager tự commit. Toàn bộ thao tác của Service con là một phần trong transaction do Service cha điều phối.

3. **Cơ chế phòng vệ của `transactional(db)` (Transaction Guard)**:
   - Utility context manager `transactional(db)` ([app/services/transaction.py](file:///e:/DuLieu/24DHTT02/HK7/LapTrinhMang/BaiTapNhom/Radius-Protocol/backend/app/services/transaction.py)) bắt buộc kiểm tra trạng thái của Session trước khi thực thi:
     * **Nếu Session đã có transaction đang hoạt động** (`db.in_transaction() == True`): Lập tức ném ngoại lệ `TransactionAlreadyActiveError`, từ chối thực thi và không tiếp tục chạy khối lệnh bên trong.
     * **Mục đích phòng ngừa**: Ngăn chặn tình huống Service con hoặc một block lồng bên trong vô tình gọi commit làm chốt dữ liệu dở dang (premature commit) của Service cha, hoặc rollback ngoài ý muốn.
     * **Khi bị từ chối**: Dữ liệu pending từ tầng ngoài được giữ nguyên trạng thái, quyền quyết định tiếp tục hoặc rollback thuộc về Service cha.
   - **Nếu Session chưa có transaction**: Khởi tạo transaction mới tường minh (`trans = db.begin()`), tự động gọi `trans.commit()` khi hoàn tất thành công, hoặc `trans.rollback()` khi phát sinh exception.
   - **Bảo toàn ngoại lệ gốc**: Sử dụng bare `raise` trong khối `except Exception:`. Nếu bản thân lệnh rollback gặp sự cố, lỗi rollback được ghi log cảnh báo mà không che khuất ngoại lệ nghiệp vụ ban đầu.

4. **Không sử dụng SAVEPOINT làm cơ chế mặc định**:
   - Hệ thống không sử dụng `begin_nested()` / SAVEPOINT ngầm định. Mô hình transaction phẳng (flat transaction model) giúp luồng dữ liệu rõ ràng, tránh các bẫy hành vi của nested savepoints trong SQLAlchemy.

5. **Giao dịch nguyên tử (Atomic Business Operations)**:
   - Mọi thao tác nghiệp vụ ghi nhiều bước phải được thực hiện trong cùng một transaction duy nhất; nếu một bước thất bại, toàn bộ phải rollback.

6. **Thao tác chỉ đọc (Read-Only Operations)**:
   - Đối với các thao tác truy vấn dữ liệu (SELECT), không mở transaction ghi và không gọi `commit()`. Khi request kết thúc, session tự động đóng sạch sẽ qua `get_db()`.

---

### 5.1. QUY ƯỚC XÁC THỰC DASHBOARD ADMIN (ADMIN AUTHENTICATION)

1. **Tách biệt với RADIUS Network Authentication**:
   - Dashboard Admin là tài khoản quản trị ứng dụng web lưu tại bảng `app_admins`.
   - Không sử dụng bảng `radcheck` hoặc giao thức RADIUS (PAP/CHAP) để xác thực Dashboard Admin.
2. **Cơ chế băm mật khẩu**:
   - Sử dụng PBKDF2-HMAC-SHA256 với 310.000 vòng lặp (`PBKDF2_ITERATIONS = 310_000`) và 16 bytes salt ngẫu nhiên từ `app/core/security.py`.
   - **Ghi chú đối chiếu tiêu chuẩn**: Đây là thông số cấu hình nội bộ đang triển khai trong Foundation. Việc đánh giá tăng work factor hoặc chuyển đổi sang các thuật toán kháng ASIC/GPU (như Argon2id) sẽ được xem xét trong các đợt Security Review chuyên sâu tiếp theo.
3. **Thao tác chỉ đọc (Read-Only)**:
   - Quá trình xác thực là truy vấn SELECT chỉ đọc qua SQLAlchemy Session tiêm từ ngoài, không gọi `commit()` hay `rollback()`, không dùng `transactional()`.
4. **Bảo vệ dữ liệu nhạy cảm**:
   - Kết quả trả về là DTO `AdminAuthResult` an toàn (chỉ chứa `id`, `username`, `email`, `role`, `is_active`, `created_at`), không chứa `password` hay `password_hash`.
5. **Giảm thiểu rủi ro Timing Attack & Username Enumeration**:
   - Hàm `verify_password()` sử dụng `hmac.compare_digest()` để so sánh digest ở mức độ hằng số thời gian, bảo vệ thao tác so sánh chuỗi hash.
   - Khi username không tồn tại trong CSDL, `AdminAuthService` thực thi `verify_password` giả lập với `DUMMY_PASSWORD_HASH` (cùng 310.000 vòng băm PBKDF2). Biện pháp này giúp giảm đáng kể sự chênh lệch thời gian xử lý CPU tính toán giữa tài khoản không tồn tại và tài khoản tồn tại nhưng sai mật khẩu.
   - Cả hai trường hợp đều trả về cùng một ngoại lệ duy nhất: `UnauthorizedError("Tên đăng nhập hoặc mật khẩu không chính xác.", code="INVALID_CREDENTIALS")` (HTTP 401).
   - *Lưu ý thực tế*: Thời gian phản hồi tổng thể của HTTP request vẫn có thể có sự biến thiên do truy vấn CSDL, điều phối luồng ASGI và tải hệ thống.
6. **Tài khoản bị vô hiệu hóa (`is_active=False`)**:
   - Bị từ chối truy cập với `ForbiddenError("Tài khoản quản trị đã bị vô hiệu hóa. Vui lòng liên hệ quản trị viên cấp cao.", code="ACCOUNT_INACTIVE")` (HTTP 403).

---

### 5.2. QUY ƯỚC JWT AUTHENTICATION CHO DASHBOARD ADMIN (JWT TOKEN FOUNDATION)

1. **Vị trí và Phân tầng**:
   - Triển khai tại `backend/app/services/admin_token.py` thông qua `AdminTokenService` và `AdminTokenClaims`.
   - Tái sử dụng các hàm mật mã chuẩn từ `app/core/security.py`. Độc lập hoàn toàn với CSDL.
2. **Cơ chế Thuật toán & Thời hạn**:
   - Thuật toán ký số: **HS256** (HMAC với SHA-256).
   - Thời hạn chuẩn của Access Token: **30 phút** (cấu hình qua `settings.ACCESS_TOKEN_EXPIRE_MINUTES`).
   - Khóa bí mật ký token: lấy từ `settings.JWT_SECRET_KEY`.
3. **Cấu trúc Claims tối thiểu và an toàn**:
   - `sub`: ID định danh duy nhất của Admin (chuỗi string, ví dụ `"42"`).
   - `role`: Vai trò của Admin (ví dụ `"superadmin"`, `"it_admin"`).
   - `type`: Bắt buộc là `"access"` để phân biệt Access Token với các token chức năng khác.
   - `iat`: Thời điểm phát hành (UNIX epoch integer).
   - `exp`: Thời điểm hết hạn (UNIX epoch integer).
   - **Tuyệt đối cấm**: Không chứa `password`, `password_hash`, DB connection string hay JWT secret.
4. **Quy tắc Kiểm định & Từ chối Token (Verification Rules)**:
   - Từ chối token sai chữ ký, sai định dạng $\rightarrow$ `UnauthorizedError(code="TOKEN_INVALID")` (HTTP 401).
   - Từ chối token hết hạn $\rightarrow$ `UnauthorizedError(code="TOKEN_EXPIRED")` (HTTP 401).
   - Từ chối token dùng thuật toán không được phép (`alg=none`, `HS384`, `RS256`,...) $\rightarrow$ `UnauthorizedError(code="TOKEN_INVALID")`.
   - Từ chối token thiếu `sub`, thiếu `role`, hoặc `type != "access"` $\rightarrow$ `UnauthorizedError(code="TOKEN_INVALID")`.
5. **DTO Trả về (`AdminTokenClaims`)**:
   - Kế thừa từ `dict` để tương thích với truy cập dạng từ điển (`claims['sub']`) lẫn thuộc tính (`claims.sub`, `claims.role`, `claims.exp`).

---

### 5.3. QUY ƯỚC CURRENT ADMIN DEPENDENCY (`get_current_admin`)

1. **Vị trí và Phân tầng**:
   - Triển khai tại `backend/app/core/admin_dependencies.py` thông qua dependency function `get_current_admin` và DTO `CurrentAdmin`.
   - Đóng vai trò cầu nối an toàn giữa HTTP Transport, JWT Token Service và SQLAlchemy ORM Layer.
2. **Cơ chế trích xuất Bearer Token**:
   - Sử dụng `HTTPBearer(auto_error=False)` kết hợp kiểm tra request header trực tiếp.
   - Chỉ chấp nhận token gửi qua header `Authorization: Bearer <token>`.
   - Từ chối thiếu Authorization header $\rightarrow$ `UnauthorizedError(code="UNAUTHORIZED")` (HTTP 401).
   - Từ chối sai scheme hoặc header rỗng $\rightarrow$ `UnauthorizedError(code="TOKEN_INVALID")` (HTTP 401).
3. **Quy trình xác minh và truy vấn**:
   - Ủy quyền kiểm tra chữ ký HS256, thời hạn sống (exp), và claims bắt buộc cho `AdminTokenService.verify_access_token()`.
   - Chuyển đổi an toàn claim `sub` sang integer ID. Truy vấn `AppAdmin` từ CSDL bằng Session inject từ `get_db()`.
   - Không tìm thấy Admin trong CSDL $\rightarrow$ `UnauthorizedError(code="TOKEN_INVALID")`.
   - Admin có `is_active=False` $\rightarrow$ `ForbiddenError(code="ACCOUNT_INACTIVE")` (HTTP 403).
4. **Bảo vệ dữ liệu nhạy cảm**:
   - Trả về DTO `CurrentAdmin(AdminAuthResult)` chỉ chứa các trường an toàn: `id`, `username`, `email`, `role`, `is_active`, `created_at`. Không chứa `password` hay `password_hash`.
5. **Ranh giới an toàn & Quản lý Session**:
   - Thao tác chỉ đọc (Read-Only query), không mở transaction ghi, không gọi `commit()` hay `rollback()`.
   - Tách biệt với FreeRADIUS: Không import hay truy vấn bảng `radcheck`.

---

### 5.4. QUY ƯỚC RBAC FOUNDATION (ROLE-BASED ACCESS CONTROL)

1. **Tập vai trò chuẩn hóa**:
   - `AdminRole.SUPERADMIN` (`"superadmin"`): Toàn quyền quản trị hệ thống.
   - `AdminRole.IT_ADMIN` (`"it_admin"`): Quản trị viên kỹ thuật mạng và người dùng.
   - `AdminRole.AUDITOR` (`"auditor"`): Kiểm toán viên, chỉ xem báo cáo và nhật ký.
2. **Nguyên tắc Deny-by-default**:
   - Mọi vai trò `None`, chuỗi rỗng, hoặc không thuộc tập `VALID_ROLES` đều bị từ chối với `ForbiddenError` (HTTP 403, code `FORBIDDEN`).
3. **Nguồn dữ liệu thẩm quyền duy nhất (Database Authority)**:
   - Quyết định phân quyền RBAC dựa vào thuộc tính `current_admin.role` được truy vấn từ bảng `app_admins` trong CSDL ở bước `get_current_admin`. Không sử dụng role claim trong JWT làm nguồn quyết định quyền hạn.
4. **Cơ chế Reusable Dependency Factory (`require_roles`)**:
   - Nhận một hoặc nhiều vai trò được phép (`*allowed_roles: Union[str, AdminRole]`).
   - Cấu hình fail-fast: Ném `ValueError` ngay tại thời điểm khởi tạo router nếu danh sách vai trò rỗng hoặc chứa role không hợp lệ.
   - Tái sử dụng `CurrentAdmin` đã được inject từ `get_current_admin`; không lặp lại giải mã JWT hay truy vấn CSDL lần thứ hai.

---

### 5.5. QUY ƯỚC ADMIN AUTHENTICATION API (`POST /api/v1/admin/auth/login`)

1. **Vị trí và Định tuyến**:
   - Triển khai tại `backend/app/routers/admin_auth.py`.
   - Router prefix: `"/api/v1/admin/auth"`
   - Endpoint: `POST /login`
   - Đường dẫn đầy đủ: `POST /api/v1/admin/auth/login` (Tags: `["Admin Authentication"]`).
2. **Hợp đồng Dữ liệu (API Contract)**:
   - **Request Schema (`AdminLoginRequest`)**: Nhận `username` (1–64 ký tự) và `password` (1–128 ký tự). Bảo toàn nguyên vẹn khoảng trắng gốc của mật khẩu.
   - **Response Schema (`AdminLoginResponse`)**:
     * `access_token`: JWT chuỗi đã ký số HS256.
     * `token_type`: Mặc định `"bearer"`.
     * `expires_in`: Thời hạn sống thực tế tính theo giây (`settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60`).
     * `admin`: DTO `AdminInfoResponse` (`id`, `username`, `email`, `role`, `is_active`, `created_at`).
   - Tuyệt đối không trả về `password`, `password_hash`, hoặc `JWT_SECRET_KEY` trong response.
3. **Luồng xử lý Service**:
   - Nhận `db: Session` qua Dependency Injection từ `get_db()`.
   - Khởi tạo `AdminAuthService(db=db)` và gọi `.authenticate(username, password)`.
   - Xác thực thành công $\rightarrow$ gọi `AdminTokenService.create_access_token(admin=admin_result)`.
4. **Xử lý lỗi**:
   - Sai username hoặc password $\rightarrow$ `UnauthorizedError(code="INVALID_CREDENTIALS")` (HTTP 401).
   - Tài khoản bị vô hiệu hóa $\rightarrow$ `ForbiddenError(code="ACCOUNT_INACTIVE")` (HTTP 403).
   - Thiếu secret ký JWT $\rightarrow$ `ServiceUnavailableError(code="SERVICE_UNAVAILABLE")` (HTTP 503).
   - Dữ liệu không hợp lệ $\rightarrow$ HTTP 422 (`VALIDATION_ERROR`).

---

### 5.6. QUY ƯỚC ADMIN IDENTITY API (`GET /api/v1/admin/auth/me`)

1. **Vị trí và Định tuyến**:
   - Endpoint: `GET /api/v1/admin/auth/me` (Tags: `["Admin Authentication"]`).
   - Yêu cầu Header: `Authorization: Bearer <access_token>`.
2. **Hợp đồng Dữ liệu**:
   - **Response Schema (`AdminInfoResponse`)**: `id`, `username`, `email`, `role`, `is_active`, `created_at`.
   - Tuyệt đối không trả về `password` hay `password_hash`.
3. **Cơ chế xác thực**:
   - Sử dụng trực tiếp dependency `current_admin: CurrentAdmin = Depends(get_current_admin)`.
   - Tái sử dụng đối tượng `CurrentAdmin` đã được xác thực và nạp từ CSDL, không truy vấn CSDL lần thứ hai.
4. **Xử lý lỗi**:
   - Thiếu hoặc sai header/token $\rightarrow$ HTTP 401 (`UNAUTHORIZED`, `TOKEN_INVALID`, `TOKEN_EXPIRED`).
   - Tài khoản bị vô hiệu hóa $\rightarrow$ HTTP 403 (`ACCOUNT_INACTIVE`).

---

### 5.7. QUY ƯỚC ADMIN PASSWORD CHANGE API (`POST /api/v1/admin/auth/change-password`)

1. **Vị trí và Định tuyến**:
   - Triển khai tại `backend/app/routers/admin_auth.py`, prefix `"/api/v1/admin/auth"`.
   - Endpoint: `POST /api/v1/admin/auth/change-password` (Tags: `["Admin Authentication"]`).
   - Yêu cầu xác thực bắt buộc: Dashboard Admin đang đăng nhập với Bearer JWT.
2. **Kiểm soát rủi ro IDOR**:
   - Định danh quản trị viên (`admin_id`) được lấy trực tiếp từ `current_admin.id` (do dependency `get_current_admin` cung cấp qua token đã xác thực).
   - Request body hoàn toàn không nhận trường ID nào, giúp kiểm soát hiệu quả rủi ro IDOR trong luồng xử lý này.
3. **Hợp đồng Dữ liệu (API Contract)**:
   - **Request Schema (`AdminChangePasswordRequest`)**:
     * `current_password` (str, 1–128 ký tự): Mật khẩu hiện tại của quản trị viên.
     * `new_password` (str, 8–128 ký tự): Mật khẩu mới cần thiết lập.
     * `confirm_password` (str, 8–128 ký tự): Mật khẩu xác nhận.
     * Validators: Bảo toàn nguyên vẹn giá trị mật khẩu (không tự ý strip khoảng trắng); model validator kiểm tra `new_password == confirm_password` (ném `ValueError("Mật khẩu xác nhận không khớp với mật khẩu mới.")` nếu không khớp).
   - **Response Schema (`AdminChangePasswordResponse`)**:
     * `message`: `"Đổi mật khẩu thành công."`.
     * `admin`: DTO `AdminInfoResponse` (`id`, `username`, `email`, `role`, `is_active`, `created_at`).
     * Tuyệt đối không trả về mật khẩu dạng rõ, `password_hash` hay `salt` ra response.
4. **Luồng xử lý nghiệp vụ và Quản lý Giao dịch (Service Implementation)**:
   - Handler nhận `db: Session = Depends(get_db, use_cache=False)` và gọi `AdminAuthService(db=db).change_password(...)`.
   - **Tách Session phục vụ Transaction**: Trong SQLAlchemy 2.0, câu lệnh SELECT đọc Admin của `get_current_admin` kích hoạt `autobegin` trên session mặc định (`db.in_transaction() == True`). Việc cấu hình `use_cache=False` là giải pháp kỹ thuật cụ thể cho endpoint đổi mật khẩu hiện tại nhằm tách Session dùng cho xác thực khỏi Session do Service sở hữu transaction, tuân thủ nguyên tắc `transactional(db)`.
   - *Định hướng cho endpoints mới*: Không quy định áp dụng máy móc `use_cache=False` cho mọi endpoint ghi dữ liệu. Với endpoint mới trong tương lai, cần đánh giá dependency graph, Session lifecycle và transaction ownership của từng trường hợp cụ thể trước khi quyết định cấu hình.
   - **Quy tắc nghiệp vụ trong Service**:
     1. Khởi tạo transaction qua `with transactional(self.db):`.
     2. Truy vấn tài khoản Admin theo `admin_id`. Nếu không thấy $\rightarrow$ ném `NotFoundError(code="ADMIN_NOT_FOUND")`.
     3. Kiểm tra trạng thái hoạt động: nếu `not admin.is_active` $\rightarrow$ ném `ForbiddenError(code="ACCOUNT_INACTIVE")`.
     4. Kiểm tra cấm trùng mật khẩu cũ: `verify_password(new_password, admin.password_hash)` $\rightarrow$ nếu trùng ném `ValidationError("Mật khẩu mới không được trùng với mật khẩu hiện tại.", code="PASSWORD_REUSED")` (HTTP 422).
     5. Xác minh mật khẩu hiện tại: `verify_password(current_password, admin.password_hash)` $\rightarrow$ nếu sai ném `UnauthorizedError("Mật khẩu hiện tại không chính xác.", code="INVALID_CREDENTIALS")` (HTTP 401).
     6. Băm mật khẩu mới bằng PBKDF2-HMAC-SHA256 (310.000 vòng, salt 16 bytes ngẫu nhiên mới).
     7. Cập nhật `admin.password_hash` và `admin.updated_at`.
     8. Trả về `AdminAuthResult` an toàn; context manager tự động gọi `commit()`.
   - **Ghi chú an ninh (Security Observation)**:
     * Thứ tự kiểm tra hiện tại trong mã nguồn: (1) Kiểm tra tài khoản hoạt động $\rightarrow$ (2) Kiểm tra mật khẩu mới có trùng mật khẩu hiện tại không (`PASSWORD_REUSED`) $\rightarrow$ (3) Xác minh mật khẩu hiện tại (`INVALID_CREDENTIALS`).
     * Thứ tự này có thể tạo ra một tín hiệu suy đoán mật khẩu (side-channel / oracle) nếu người gọi sở hữu một JWT hợp lệ nhưng không biết mật khẩu hiện tại (ví dụ: token bị đánh cắp): kẻ tấn công có thể thử các mật khẩu mới; nếu API phản hồi HTTP 422 `PASSWORD_REUSED` thay vì HTTP 401 `INVALID_CREDENTIALS`, kẻ đó suy ra được mật khẩu hiện tại của tài khoản.
     * Khuyến nghị cho đợt Security Review chuyên sâu tiếp theo: Đảo lại thứ tự kiểm tra — xác minh `current_password` thành công trước, sau đó mới kiểm tra `PASSWORD_REUSED`.
     * *Lưu ý*: Đây là Security Observation kỹ thuật được ghi nhận để đánh giá và xử lý theo quy trình, không phải thay đổi mã nguồn trong Step 1.3.
5. **Ánh xạ Mã trạng thái HTTP & Error Codes**:
   - `200 OK`: Đổi mật khẩu thành công.
   - `401 Unauthorized`: Mật khẩu hiện tại không chính xác (`INVALID_CREDENTIALS`), thiếu token (`UNAUTHORIZED`), token sai hoặc hết hạn (`TOKEN_INVALID`, `TOKEN_EXPIRED`).
   - `403 Forbidden`: Tài khoản quản trị bị vô hiệu hóa (`ACCOUNT_INACTIVE`).
   - `404 Not Found`: Không tìm thấy tài khoản quản trị (`ADMIN_NOT_FOUND`).
   - `422 Unprocessable Entity`: Mật khẩu xác nhận không khớp, mật khẩu mới dưới 8 ký tự, hoặc mật khẩu mới trùng mật khẩu cũ (`VALIDATION_ERROR`, `PASSWORD_REUSED`).
   - `500 Internal Server Error`: Sự cố giao dịch hoặc lỗi máy chủ nội bộ (`INTERNAL_SERVER_ERROR`).

---

### 5.8. KIẾN TRÚC KIỂM THỬ HTTP INTEGRATION (HTTP INTEGRATION TEST ARCHITECTURE)

Bộ kiểm thử HTTP Integration của Admin Password Change ([backend/test_admin_change_password_http_integration.py](file:///e:/DuLieu/24DHTT02/HK7/LapTrinhMang/BaiTapNhom/Radius-Protocol/backend/test_admin_change_password_http_integration.py)) được xây dựng theo chuẩn Async-Native:

1. **Khung kiểm thử và Cơ chế Client**:
   - Sử dụng `@pytest.mark.anyio` cho toàn bộ các async test functions.
   - Khởi tạo client thông qua `httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")`.
   - Request HTTP đi qua toàn bộ pipeline ASGI thực tế của FastAPI (routing, dependency injection, authentication, validation, service execution, exception handling mapping và response serialization).
2. **Cơ chế Snapshot và Restore Dependency Overrides**:
   - Triển khai context manager `admin_auth_dependency_scope(db_factory, token_service)`:
     ```python
     @asynccontextmanager
     async def admin_auth_dependency_scope(
         db_factory: Any,
         token_service: AdminTokenService,
     ) -> AsyncGenerator[httpx.AsyncClient, None]:
         original_overrides = dict(app.dependency_overrides)
         def override_get_db(): ...
         def override_token_service(): ...
         try:
             app.dependency_overrides[get_db] = override_get_db
             app.dependency_overrides[get_admin_token_service] = override_token_service
             transport = httpx.ASGITransport(app=app)
             async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                 yield client
         finally:
             app.dependency_overrides.clear()
             app.dependency_overrides.update(original_overrides)
     ```
   - **Bảo vệ toàn diện**: Khối `try/finally` bao phủ cả quá trình gán override, tạo client và khối test execution. Đảm bảo `app.dependency_overrides` được khôi phục nguyên vẹn 100% khi khởi tạo lỗi, khi test body có exception, cũng như khi test hoàn tất bình thường.
   - **Thực thi xác thực thật và cơ chế CSDL kiểm thử**:
     * Token JWT được tạo và xác minh qua luồng authentication thực tế của hệ thống.
     * Dependency `get_current_admin` được thực thi thật, không bị override.
     * Truy vấn thông tin Admin được thực hiện trên cơ sở dữ liệu kiểm thử SQLite in-memory cô lập (không có nghĩa là truy vấn MariaDB production hoặc MariaDB staging thật).
     * Thiết kế này bảo đảm kiểm thử bao phủ toàn bộ pipeline ASGI thực tế mà vẫn duy trì tính cô lập tuyệt đối của Phase 0B.
3. **Loại bỏ Monkeypatching Toàn cục**:
   - Không can thiệp vào `BaseSelectorEventLoop` internals (`_make_self_pipe`, `_close_self_pipe`, `_write_to_self`).
   - Không thay đổi `asyncio.set_event_loop_policy`.
   - Không monkeypatch `anyio.to_thread.run_sync` hay `starlette.concurrency.run_in_threadpool`.
4. **Môi trường Cô lập**:
   - Sử dụng SQLite in-memory (`sqlite:///:memory:`) với `StaticPool` (`check_same_thread=False`).
   - Mỗi test fixture tạo engine/session riêng biệt, gọi `create_all()` khi setup và `drop_all()` kèm `dispose()` khi teardown.
   - *Phạm vi bằng chứng*: Bộ test này chứng minh tính đúng đắn của logic HTTP ASGI pipeline và SQLAlchemy session management trong môi trường kiểm thử cô lập; không đóng vai trò kiểm thử trên MariaDB hoặc FreeRADIUS thật.
5. **Quy mô Kiểm thử**:
   - Gồm 26 test functions (với các parameterized test cases, tổng cộng 32 test invocations), đạt tỷ lệ 32/32 PASSED.

---

## 6. QUY TẮC XỬ LÝ LỖI & ÁNH XẠ HTTP (GLOBAL EXCEPTION HANDLING CONTRACT)

Hệ thống triển khai cơ chế xử lý ngoại lệ tập trung tại `backend/app/core/exception_handlers.py`:

1. **Chuẩn hóa cấu trúc JSON Error Response**:
   ```json
   {
     "error": {
       "code": "<ERROR_CODE>",
       "message": "<ERROR_MESSAGE>"
     }
   }
   ```
2. **Bảng ánh xạ Business Exceptions sang HTTP Response**:

   | Business Exception | HTTP Status Code | Default Error Code | Ý nghĩa nghiệp vụ |
   | :--- | :---: | :--- | :--- |
   | `NotFoundError` | **404** Not Found | `RESOURCE_NOT_FOUND` | Không tìm thấy tài nguyên yêu cầu. |
   | `ConflictError` | **409** Conflict | `RESOURCE_CONFLICT` | Trùng lặp dữ liệu (Username đã tồn tại). |
   | `UnauthorizedError` | **401** Unauthorized | `UNAUTHORIZED` | Thiếu token, sai mật khẩu, token hết hạn/sai chữ ký. |
   | `ForbiddenError` | **403** Forbidden | `FORBIDDEN` | Tài khoản bị vô hiệu hóa hoặc không đủ quyền RBAC. |
   | `ServiceUnavailableError` | **503** Service Unavailable | `SERVICE_UNAVAILABLE` | Thiếu JWT secret, DB offline hoặc FreeRADIUS không phản hồi. |
   | `ValidationError` | **422** Unprocessable Entity | `VALIDATION_ERROR` | Vi phạm quy tắc kiểm tra nghiệp vụ (ví dụ: trùng mật khẩu cũ). |
   | `TransactionAlreadyActiveError` | **500** Internal Server Error | `INTERNAL_SERVER_ERROR` | Vi phạm ranh giới giao dịch nội bộ; che giấu chi tiết với client. |
   | `Exception` (Unhandled) | **500** Internal Server Error | `INTERNAL_SERVER_ERROR` | Lỗi máy chủ chưa phân loại; log traceback nội bộ và che giấu client. |

3. **Bảo tồn cơ chế mặc định của FastAPI**:
   - `HTTPException` và `StarletteHTTPException`: Được re-raise để FastAPI tự xử lý theo định dạng mặc định (`{"detail": "..."}`), đảm bảo tương thích với endpoint `/auth/login` và tài liệu `/docs`.
   - `RequestValidationError`: Giữ nguyên handler mặc định của FastAPI (HTTP 422 `{"detail": [...]}`).

---

## 7. QUY TẮC BẢO VỆ DỮ LIỆU NHẠY CẢM (SECURITY & DATA PRIVACY)

1. **Dữ liệu cấm trả về Client**:
   - Cột `pass` trong bảng `radpostauth`.
   - Cột `secret` trong bảng `nas`.
   - Cột `password_hash` trong bảng `app_admins`: Tuyệt đối không serialize vào Pydantic response schema.
   - Cột `value` (Cleartext-Password) trong bảng `radcheck`.
2. **Kiến trúc bảng `app_users`**:
   - Bảng `app_users` là hồ sơ định danh mở rộng, **không chứa cột `password` hoặc `password_hash`**. Mật khẩu mạng người dùng do FreeRADIUS quản lý tại bảng `radcheck`.
3. **Bảo toàn dữ liệu lịch sử**:
   - Không thiết lập `CASCADE DELETE` từ `app_users` sang `radacct` hoặc `radpostauth` để bảo đảm tính toàn vẹn kiểm toán mạng (Audit Trail).

---

## 8. BẢNG ĐỐI CHIẾU: THÀNH PHẦN HIỆN CÓ VÀ ĐỊNH HƯỚNG TƯƠNG LAI

| Thành phần | Đã triển khai và Nghiệm thu (Foundation) | Định hướng triển khai Phase tiếp theo |
| :--- | :--- | :--- |
| **Configuration** | `app/core/config.py` (BaseSettings, masking `__repr__`) | Bổ sung dynamic reload nếu cần |
| **Security** | `app/core/security.py` (PBKDF2 310k, PyJWT HS256, hmac digest) | Đánh giá work factor / Argon2id, Token Blacklist |
| **Dependencies & RBAC** | `app/core/dependencies.py` (`get_db`, ping, sanitizer), `app/core/admin_dependencies.py` (`get_current_admin`), `app/core/rbac.py` (`require_roles`, `AdminRole`) | Rate limiting dependencies, Resource-level policy checks |
| **ORM Models** | 9 bảng FreeRADIUS + 2 bảng App (`app/models/`) | Tối ưu hóa query indexes |
| **Schema Verifier**| `app/models/verifier.py` (Read-only, 11 tables verified) | On-demand admin API check |
| **Routers** | `app/routers/health.py`, `app/routers/admin_auth.py` (`/login`, `/me`, `/change-password`) | `users.py`, `groups.py`, `accounting.py` |
| **Services** | Contract (`app/services/base.py`, `transaction.py`), `AdminAuthService`, `AdminTokenService` | `UserService`, `GroupService`, `NasService` |
| **Exception Handling** | `app/core/exceptions.py`, `app/core/exception_handlers.py` | Ánh xạ thêm các exception domain nghiệp vụ mở rộng |
| **Schemas** | Package `app/schemas/` (Admin Login, Info, ChangePassword DTOs) | DTOs cho User CRUD, Group CRUD, Session Logs |

---

## 9. BẰNG CHỨNG KIỂM THỬ HỒI QUY (FOUNDATION REGRESSION EVIDENCE)

Toàn bộ **15 test files** thuộc Foundation Regression Suite được thực thi độc lập trong môi trường kiểm thử cô lập (SQLite in-memory, không kết nối dịch vụ thật), ghi nhận kết quả thực nghiệm sau:

| Phân hệ / Nhóm kiểm thử | Danh sách Test Files | Số lượng Tests | Kết quả Thực tế | Thời gian Thực thi | Exit Code |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Foundation Infrastructure** | `test_database_foundation.py` (27)<br>`test_core_security.py` (12)<br>`test_service_foundation.py` (15)<br>`test_exception_handlers.py` (14)<br>`test_app_health.py` (9) | 77 | **77 PASS / 0 FAIL** | 3.36s | 0 |
| **Admin Auth & Identity** | `test_admin_auth.py` (15)<br>`test_admin_token.py` (22)<br>`test_admin_dependencies.py` (23)<br>`test_rbac.py` (17)<br>`test_admin_login_api.py` (18)<br>`test_admin_me_api.py` (16)<br>`test_admin_me_http_integration.py` (12) | 123 | **123 PASS / 0 FAIL** | 29.55s | 0 |
| **Change Password Suite** | `test_admin_change_password_service.py` (18)<br>`test_admin_change_password_api.py` (16)<br>`test_admin_change_password_http_integration.py` (32) | 66 | **66 PASS / 0 FAIL** | 31.10s | 0 |
| **TỔNG CỘNG FOUNDATION** | **15 test files** | **266** | **266 PASS / 0 FAIL / 0 SKIPPED** | **64.01s** | **0** |

### Giới hạn Kiểm thử và Các Bài Test Không Chạy
- `backend/test_integration.py`: **Không chạy** do yêu cầu kết nối trực tiếp đến CSDL MariaDB thật và bảng `radcheck`.
- `backend/test_radius.py`: **Không chạy** do yêu cầu gửi gói tin UDP đến máy chủ FreeRADIUS daemon thật.
- `backend/test_unit.py`: **Không chạy** do là test unit legacy của Phase 0A, không nằm trong danh mục Foundation Regression Suite của Phase 0B.
- *Lưu ý quan trọng*: Kết quả 266 PASS nêu trên là bằng chứng kiểm thử trong môi trường cô lập, không đại diện cho việc toàn bộ hệ thống đã được kiểm chứng end-to-end trên MariaDB và FreeRADIUS thật.

---

## 10. SỔ ĐĂNG KÝ NỢ KỸ THUẬT VÀ PHÁT HIỆN KIẾN TRÚC (TECHNICAL DEBT & FINDINGS REGISTER)

Các phát hiện kỹ thuật được ghi nhận từ đợt kiểm toán Step 1.2, toàn bộ đều ở mức độ không chặn (**Non-blocking**) đối với việc nghiệm thu Foundation:

| Finding ID | Mức độ | Vị trí Mã nguồn | Mô tả Vấn đề Kiến trúc | Khuyến nghị Xử lý (Kế hoạch Phase 1 & 2) | Trạng thái Chặn |
| :---: | :---: | :--- | :--- | :--- | :---: |
| **F-01** | **MEDIUM** | [app/schemas/__init__.py](file:///e:/DuLieu/24DHTT02/HK7/LapTrinhMang/BaiTapNhom/Radius-Protocol/backend/app/schemas/__init__.py)<br>[app/schemas.py](file:///e:/DuLieu/24DHTT02/HK7/LapTrinhMang/BaiTapNhom/Radius-Protocol/backend/app/schemas.py) | **Tồn tại song song file `schemas.py` và package `schemas/`**: Package init phải dùng `importlib.util` nạp động `LoginRequest`/`LoginResponse`. | Di chuyển schemas RADIUS PAP vào `app/schemas/radius.py`, re-export trong `app/schemas/__init__.py` và xóa file `schemas.py` (Phase 1 Setup). | **Non-blocking** |
| **F-02** | **MEDIUM** | [app/core/__init__.py](file:///e:/DuLieu/24DHTT02/HK7/LapTrinhMang/BaiTapNhom/Radius-Protocol/backend/app/core/__init__.py) | **Nguy cơ circular import và coupling sâu do eager import**: `core/__init__.py` nạp sớm `admin_dependencies` $\rightarrow$ `services.admin_auth`. | Loại bỏ eager import `admin_dependencies` khỏi `core/__init__.py`; quy định caller import trực tiếp từ submodule chuyên biệt (Phase 1 Setup). | **Non-blocking** |
| **F-03** | **LOW** | [app/routers/admin_auth.py](file:///e:/DuLieu/24DHTT02/HK7/LapTrinhMang/BaiTapNhom/Radius-Protocol/backend/app/routers/admin_auth.py#L138) | **Ghi nhận lý do tách Session qua `use_cache=False` tại endpoint đổi mật khẩu**: Giải pháp kỹ thuật cụ thể nhằm tránh xung đột autobegin với `transactional(db)`. | Đã văn bản hóa tại mục 5.7 tài liệu kiến trúc. Yêu cầu đánh giá dependency graph riêng cho từng endpoint mới thay vì áp dụng máy móc (Phase 1/2). | **Non-blocking** |
| **F-04** | **LOW** | [backend/ARCHITECTURE.md](file:///e:/DuLieu/24DHTT02/HK7/LapTrinhMang/BaiTapNhom/Radius-Protocol/backend/ARCHITECTURE.md) | **Tài liệu kiến trúc cần cập nhật đồng bộ các bước Step 1.1 và 1.2**. | Hoàn thành nâng cấp tài liệu kiến trúc lên phiên bản 1.9.0 trong Step 1.3. | **Non-blocking** |
| **F-05** | **INFO** | [app/services/admin_token.py](file:///e:/DuLieu/24DHTT02/HK7/LapTrinhMang/BaiTapNhom/Radius-Protocol/backend/app/services/admin_token.py) | **Chưa có cơ chế Token Revocation / Blacklist cho JWT**: Token sống 30 phút theo cơ chế hoàn toàn stateless. | Nghiên cứu bổ sung Redis token blacklist hoặc danh sách thu hồi token khi triển khai tính năng Đăng xuất Admin (Phase 2). | **Non-blocking** |
| **F-06** | **INFO** | [app/database.py](file:///e:/DuLieu/24DHTT02/HK7/LapTrinhMang/BaiTapNhom/Radius-Protocol/backend/app/database.py) | **SQLite in-memory không thay thế hoàn toàn kiểm thử tương thích MariaDB InnoDB**: Bỏ qua các đặc thù khóa dòng và isolation levels. | Chuẩn bị môi trường Docker Compose chứa MariaDB và FreeRADIUS cô lập để chạy kiểm thử tích hợp thực tế (Phase 1 Staging). | **Non-blocking** |

---

## 11. LỊCH SỬ THAY ĐỔI TÀI LIỆU (CHANGELOG)

| Phiên bản | Ngày cập nhật | Người thực hiện | Tóm tắt nội dung thay đổi |
| :---: | :---: | :---: | :--- |
| **1.0.0** | 19/10/2026 | Architecture Team | Khởi tạo tài liệu kiến trúc ban đầu cho module xác thực FreeRADIUS PAP (Phase 0A). |
| **1.5.0** | 04/11/2026 | Architecture Team | Bổ sung phân tầng Database Engine, ORM Models (11 bảng), Session lifecycle và Schema Verifier (Phase 0B Step 3.2). |
| **1.7.0** | 05/11/2026 | Architecture Team | Bổ sung Service Layer Contract, Explicit Top-level Transaction Ownership và Global Exception Handlers (Phase 0B Step 3.3). |
| **1.8.0** | 13/11/2026 | Architecture Team | Bổ sung phân hệ Dashboard Admin Authentication, JWT Token Service, Current Admin Dependency, RBAC Foundation và Admin Login/Me API (Phase 0B Step 3.4). |
| **1.8.1** | 14/11/2026 | Architecture Team | Hardening tài liệu & hoàn thiện mô tả HTTP integration testing cho Admin Identity API (Step 3.4.6-HF). |
| **1.9.0** | 16/11/2026 | Senior Backend Architect | **Hoàn thiện Foundation Architecture Documentation (Step 1.3)**:<br>- Bổ sung mục 5.7: Quy ước Admin Password Change API (`POST /change-password`), kiểm soát IDOR, schemas, quy tắc cấm trùng mật khẩu cũ và error mapping.<br>- Bổ sung mục 5.8: Kiến trúc kiểm thử HTTP Integration qua FastAPI ASGI pipeline, AnyIO async native, snapshot/restore overrides, loại bỏ global monkeypatching.<br>- Bổ sung giải thích kỹ thuật phân tách Session qua `use_cache=False` và định hướng đánh giá dependency graph cho endpoints mới.<br>- Bổ sung mục 9: Bằng chứng thực nghiệm 266 Foundation Regression Tests (15 files) và các giới hạn kiểm thử.<br>- Bổ sung mục 10: Sổ đăng ký nợ kỹ thuật và phát hiện kiến trúc (Findings F-01 đến F-06).<br>- Chuẩn hóa kiểm kê 27 physical source files và 15 test files. Điều chỉnh các nhận định bảo mật về PBKDF2/OWASP và timing attack phù hợp với bằng chứng mã nguồn. |
