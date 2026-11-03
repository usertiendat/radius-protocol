# TÀI LIỆU KIẾN TRÚC BACKEND (ARCHITECTURE CONTRACT)
## RADIUS Enterprise Authentication & Access Control System

> **Phiên bản tài liệu**: 1.1.0 — Phase 0B Step 3.3.2 (Transaction Safety Update)  
> **Cập nhật ngày**: 04/11/2026  
> **Trạng thái**: Đã nghiệm thu nền tảng (Foundation Accepted)

---

## 1. TỔNG QUAN KIẾN TRÚC PHÂN LỚP (LAYERED ARCHITECTURE)

Hệ thống Backend được xây dựng trên nền tảng **FastAPI (v0.146.0)** kết hợp **SQLAlchemy 2.x ORM** và **FreeRADIUS 3.x / MariaDB**. Cấu trúc thư mục tuân thủ nghiêm ngặt mô hình phân tầng trách nhiệm (Separation of Concerns):

```
backend/
├── app/
│   ├── core/                  # Cấu hình tập trung, bảo mật và dependencies nền tảng
│   │   ├── config.py          # Pydantic BaseSettings, tự động nạp .env
│   │   ├── security.py        # PBKDF2-HMAC-SHA256 (310k iterations), PyJWT (HS256)
│   │   └── dependencies.py    # Database Session lifecycle, DB health check, error sanitizer
│   ├── models/                # SQLAlchemy ORM Models & Schema Protection
│   │   ├── radius.py          # 9 bảng chuẩn FreeRADIUS (radcheck, radacct, nas, ...)
│   │   ├── application.py     # 2 bảng quản trị ứng dụng (app_admins, app_users)
│   │   └── verifier.py        # Read-only Schema Verifier (tương thích MariaDB & SQLite)
│   ├── schemas/               # Pydantic Request Validation & Response Serialization
│   │   ├── __init__.py        # Re-export và quản trị schemas
│   │   └── (tương lai)        # Schemas cho Admin, User, Group, Accounting
│   ├── services/              # Pure Business Logic Layer (độc lập với HTTP transport)
│   │   ├── __init__.py        # Service Layer Contract
│   │   └── (tương lai)        # AdminService, UserService, GroupService, AcctService
│   ├── routers/               # API Endpoints & HTTP Request/Response mapping
│   │   ├── health.py          # GET /health, GET /health/database
│   │   └── (tương lai)        # auth.py, users.py, groups.py, accounting.py
│   ├── database.py            # SQLAlchemy Engine singleton, SessionLocal, get_db()
│   ├── main.py                # FastAPI Application instance & router registration
│   ├── radius_auth.py         # Module xác thực trực tiếp FreeRADIUS (PAP qua pyrad2)
│   └── schemas.py             # Schema kế thừa (LoginRequest, LoginResponse)
├── test_core_security.py      # Unit tests nhóm Core & Security (12 tests)
├── test_database_foundation.py# Unit tests nhóm Database Engine & ORM (27 tests)
└── test_app_health.py         # Unit tests nhóm Health Monitoring (9 tests)
```

---

## 2. PHÂN ĐỊNH TRÁCH NHIỆM TỪNG TẦNG

| Phân tầng | Trách nhiệm chính | Trạng thái hiện tại |
| :--- | :--- | :---: |
| **Core** (`app/core/`) | Nạp biến môi trường an toàn, băm mật khẩu PBKDF2, phát hành/giải mã JWT token, kiểm tra kết nối CSDL, lọc bỏ secret khỏi log lỗi. | **Đã triển khai & nghiệm thu** |
| **Models** (`app/models/`) | Khai báo cấu trúc bảng CSDL (9 bảng FreeRADIUS + 2 bảng App), ràng buộc khóa chính, unique, index. Kiểm định toàn vẹn schema ở chế độ Read-Only. | **Đã triển khai & nghiệm thu** |
| **Routers** (`app/routers/`) | Nhận HTTP request, điều phối dependency injection (`get_db`), gọi Service tương ứng, ánh xạ exception thành HTTP status code. | **Đã triển khai health.py**; Routers nghiệp vụ là định hướng Phase 1 |
| **Services** (`app/services/`) | Xử lý logic nghiệp vụ, kiểm tra quy tắc kinh doanh, thực hiện thao tác ORM qua `Session` được tiêm từ router, phân định transaction. | **Đã thiết lập Contract**; Implementation cụ thể là định hướng Phase 1 |
| **Schemas** (`app/schemas/`) | Định nghĩa DTOs bằng Pydantic: kiểm tra tính hợp lệ dữ liệu đầu vào (validation), định dạng dữ liệu đầu ra, che giấu các trường nhạy cảm. | **Đã khởi tạo package & schemas kế thừa**; Schemas mở rộng là định hướng Phase 1 |

---

## 3. LUỒNG XỬ LÝ DỮ LIỆU CHUẨN (REQUEST-RESPONSE FLOW)

```
[ Client / Frontend ]
         │  (HTTP Request JSON)
         ▼
[ FastAPI Router ] (app/routers/)
  ├── 1. Pydantic validate request body (app/schemas/)
  ├── 2. Nhận Session qua Dependency Injection (Depends(get_db))
  ├── 3. Gọi Service function và truyền session: service.do_action(db, data)
  │        │
  │        ▼
  │   [ Service Layer ] (app/services/)
  │     ├── 4. Thực thi Business Rules
  │     ├── 5. Truy vấn / Ghi dữ liệu qua ORM Models (app/models/)
  │     ├── 6. Quản lý Transaction: db.commit() hoặc db.rollback()
  │     └── 7. Trả về Domain Object / DTO (hoặc ném Business Exception)
  │        │
  │        ▲
  ├── 8. Bắt Business Exception và chuyển thành HTTPException (4xx / 5xx)
  └── 9. Định dạng Response DTO an toàn qua Schema
         │  (HTTP Response JSON)
         ▼
[ Client / Frontend ]
```

---

## 4. QUY TẮC DEPENDENCY INJECTION & SESSION LIFECYCLE

1. **Session per-request**: Mỗi request HTTP chỉ sử dụng một session duy nhất, lấy từ generator `get_db()` (`SessionLocal()`).
2. **Tái sử dụng Engine Singleton**: Tuyệt đối không tạo `create_engine()` mới theo từng request. Tất cả các session liên kết với singleton `engine` trong `app/database.py` (pool size=10, max_overflow=20, pool_recycle=3600).
3. **Đóng Session tuyệt đối trong `finally`**: Bất kể request thành công hay gặp lỗi nghiêm trọng, khối `finally: db.close()` luôn được thực thi để hoàn trả kết nối về pool.
4. **Tự động Rollback khi Exception**: Nếu có ngoại lệ phát sinh chưa xử lý trong request, `get_db()` sẽ gọi `db.rollback()` trước khi đóng session để bảo vệ toàn vẹn dữ liệu.
5. **Import hoàn toàn Lazy**: Quá trình import module (`database.py`, `dependencies.py`, `main.py`) tuyệt đối không mở socket kết nối tới MariaDB.

---

## 5. QUY TẮC QUẢN LÝ GIAO DỊCH (TRANSACTION OWNERSHIP)

Hệ thống áp dụng mô hình **Explicit Top-level Transaction Ownership** (Quyền sở hữu giao dịch tường minh ở cấp cao nhất):

1. **Chỉ Service cấp cao nhất (Top-level Service) quản lý Transaction**:
   - Quyền khởi tạo, commit hoặc rollback transaction thuộc độc quyền về Service cấp cao nhất (entry-point service được gọi trực tiếp từ Router).
   - Router hoặc ORM Models tuyệt đối không can thiệp vào transaction lifecycle.

2. **Service con (Child Services / Helper Services) không tự ý commit/rollback**:
   - Khi một Service gọi các Service con hoặc Helper functions để hoàn thành một phần việc, session được truyền xuyên suốt qua tham số `db: Session`.
   - Các Service con tuyệt đối không được gọi `db.commit()`, `db.rollback()` hoặc bọc trong context manager tự commit. Toàn bộ thao tác của Service con là một phần trong transaction do Service cha điều phối.

3. **Cơ chế phòng vệ của `transactional(db)` (Transaction Guard)**:
   - Utility context manager `transactional(db)` (`app/services/transaction.py`) bắt buộc kiểm tra trạng thái của Session trước khi thực thi:
     * **Nếu Session đã có transaction đang hoạt động** (`db.in_transaction() == True`): Lập tức ném ngoại lệ `TransactionAlreadyActiveError`, từ chối thực thi và không tiếp tục chạy khối lệnh bên trong.
     * **Mục đích phòng ngừa**: Ngăn chặn triệt để tình huống Service con hoặc một block lồng bên trong vô tình gọi commit làm chốt dữ liệu dở dang (premature commit) của Service cha, hoặc rollback ngoài ý muốn.
     * **Khi bị từ chối**: Dữ liệu pending từ tầng ngoài hoàn toàn được giữ nguyên trạng thái, quyền quyết định tiếp tục hoặc rollback hoàn toàn thuộc về Service cha.
   - **Nếu Session chưa có transaction**: Khởi tạo transaction mới tường minh (`trans = db.begin()`), tự động gọi `trans.commit()` khi hoàn tất thành công, hoặc `trans.rollback()` khi phát sinh exception.
   - **Bảo toàn ngoại lệ gốc**: Sử dụng bare `raise` trong khối `except Exception:`. Nếu bản thân lệnh rollback gặp sự cố (ví dụ mất kết nối mạng), lỗi rollback chỉ được ghi log cảnh báo mà không che khuất ngoại lệ nghiệp vụ ban đầu.

4. **Không sử dụng SAVEPOINT làm cơ chế mặc định**:
   - Hệ thống không tự ý sử dụng `begin_nested()` / SAVEPOINT ngầm định. Mô hình transaction phẳng (flat transaction model) với quyền sở hữu duy nhất từ Service cha giúp đơn giản hóa việc phân tích luồng dữ liệu, tránh sự phức tạp và các bẫy hành vi của nested savepoints trong SQLAlchemy.

5. **Giao dịch nguyên tử (Atomic Business Operations)**:
   - Mọi thao tác nghiệp vụ ghi nhiều bước (ví dụ: tạo người dùng trong `app_users` và thêm thuộc tính Cleartext-Password vào `radcheck`) phải được thực hiện trong cùng một transaction duy nhất; nếu một bước thất bại, toàn bộ phải rollback.

6. **Thao tác chỉ đọc (Read-Only Operations)**:
   - Đối với các thao tác truy vấn dữ liệu (SELECT), không mở transaction ghi và không gọi `commit()`. Khi request kết thúc, session tự động đóng sạch sẽ qua `get_db()`.

---

## 6. QUY TẮC XỬ LÝ LỖI GIỮA SERVICE VÀ ROUTER (ERROR HANDLING CONTRACT)

1. **Phân biệt rành mạch giữa Business Exception và Infrastructure Exception**:
   - **Business Exception** (`app/core/exceptions.py`): Phát sinh từ tầng Service khi dữ liệu hoặc quy trình vi phạm logic kinh doanh (ví dụ: `NotFoundError` - 404, `ConflictError` - 409, `UnauthorizedError` - 401, `ForbiddenError` - 403, `ServiceUnavailableError` - 503, `ValidationError` - 422). Các ngoại lệ này độc lập hoàn toàn với FastAPI, mang mã lỗi (`code`) và HTTP metadata (`http_status`).
   - **Infrastructure Exception** (như `OperationalError`, `IntegrityError`, `PyMySQL.Error`, socket timeout): Phát sinh từ driver, kết nối mạng hoặc database server. Các lỗi này phải được tầng Service hoặc dependencies bắt và xử lý an toàn, chuyển hóa thành Business Exception tương ứng, tuyệt đối không trả raw exception ra Client.
2. **Tuyệt đối không đặt `HTTPException` trong Service**:
   - Tầng Service hoàn toàn không phụ thuộc vào FastAPI và không raise `HTTPException`.
   - Router là tầng duy nhất có thẩm quyền bắt `BaseBusinessException` và ánh xạ thành `HTTPException` với HTTP status code và payload JSON tương ứng.
3. **Router chịu trách nhiệm HTTP Status Codes**:
   - `NotFoundError` → `HTTPException(status_code=404, detail=exc.message)`
   - `ConflictError` → `HTTPException(status_code=409, detail=exc.message)`
   - `UnauthorizedError` → `HTTPException(status_code=401, detail=exc.message)`
   - `ForbiddenError` → `HTTPException(status_code=403, detail=exc.message)`
   - `ServiceUnavailableError` / `DatabaseConnectionError` → `HTTPException(status_code=503, detail=exc.message)`
   - `ValidationError` → `HTTPException(status_code=422, detail=exc.message)`
4. **Bảo vệ thông tin hạ tầng và dữ liệu nhạy cảm**:
   - Bất kỳ thông báo lỗi nào trả về cho Client hoặc ghi vào log hệ thống đều phải đi qua `sanitize_database_error()` để loại bỏ mật khẩu, chuỗi kết nối và SQL query nhạy cảm. Không trả database URL, raw traceback hay credentials cho Client.
5. **Xử lý vi phạm ranh giới giao dịch (`TransactionAlreadyActiveError`)**:
   - Ngoại lệ `TransactionAlreadyActiveError` phát sinh khi có vi phạm ranh giới sở hữu giao dịch (ví dụ Service con cố tình gọi `transactional()` trên Session đã active). Khi xảy ra, đây là lỗi phát hiện sớm lỗi lập trình (design contract violation), ngăn chặn triệt để nguy cơ làm biến dạng dữ liệu và hỗ trợ chẩn đoán chính xác luồng nghiệp vụ.

---

## 7. QUY TẮC BẢO VỆ DỮ LIỆU NHẠY CẢM (SECURITY & DATA PRIVACY)

1. **Dữ liệu tuyệt đối cấm trả về Client**:
   - Cột `pass` trong bảng `radpostauth`: Lịch sử xác thực không bao giờ trả về mật khẩu.
   - Cột `secret` trong bảng `nas`: Shared secret của thiết bị mạng chỉ dùng nội bộ giữa FreeRADIUS và NAS.
   - Cột `password_hash` trong bảng `app_admins`: Chỉ lưu mã băm PBKDF2, không bao giờ serialize vào Pydantic response schema.
   - Cột `value` (Cleartext-Password) trong bảng `radcheck`: Chỉ quản trị viên có quyền hạn cao nhất mới được phép đặt lại mật khẩu; không serialize trực tiếp trong danh sách user thông thường.
2. **Kiến trúc bảng `app_users`**:
   - Bảng `app_users` là hồ sơ định danh mở rộng (profile metadata), **tuyệt đối không chứa cột `password` hoặc `password_hash`**. Mật khẩu mạng người dùng do FreeRADIUS quản lý tại bảng `radcheck`.
3. **Bảo toàn dữ liệu lịch sử**:
   - Tuyệt đối không thiết lập `CASCADE DELETE` từ `app_users` sang `radacct` (Accounting) hoặc `radpostauth` (Post-Auth logs) để bảo đảm tính toàn vẹn kiểm toán mạng (Audit Trail).

---

## 8. BẢNG ĐỐI CHIẾU: THÀNH PHẦN HIỆN CÓ VÀ ĐỊNH HƯỚNG TƯƠNG LAI

| Thành phần | Đã triển khai và Nghiệm thu | Định hướng triển khai Phase tiếp theo |
| :--- | :--- | :--- |
| **Configuration** | `app/core/config.py` (BaseSettings, masking `__repr__`) | Bổ sung dynamic reload nếu cần |
| **Security** | `app/core/security.py` (PBKDF2 310k, PyJWT HS256) | Refresh Token, Token Blacklist |
| **Dependencies** | `app/core/dependencies.py` (`get_db`, connection ping, error sanitizer) | `get_current_admin`, RBAC permission checks |
| **ORM Models** | 9 bảng FreeRADIUS + 2 bảng App (`app/models/`) | Tối ưu hóa query indexes |
| **Schema Verifier**| `app/models/verifier.py` (Read-only, 11 tables verified) | On-demand admin API check |
| **Routers** | `app/routers/health.py` (`/health`, `/health/database`) | `auth.py`, `users.py`, `groups.py`, `accounting.py` |
| **Services** | Chuẩn hóa Contract (`app/services/__init__.py`) | `AdminAuthService`, `UserManagementService`, `RadiusConfigService` |
| **Schemas** | Package `app/schemas/`, `LoginRequest`, `LoginResponse` | DTOs cho User CRUD, Admin Login, Session Logs |
