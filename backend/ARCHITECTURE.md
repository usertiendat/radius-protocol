# TÀI LIỆU KIẾN TRÚC BACKEND (ARCHITECTURE CONTRACT)
## RADIUS Enterprise Authentication & Access Control System

> **Phiên bản tài liệu**: 1.4.0 — Phase 0B Step 3.4.2 (JWT Authentication Foundation)  
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
│   │   ├── dependencies.py    # Database Session lifecycle, DB health check, error sanitizer
│   │   ├── exceptions.py      # Business Exception Contract (BaseBusinessException, NotFoundError,...)
│   │   └── exception_handlers.py # Global Exception Handlers & HTTP Error Mapping
│   ├── models/                # SQLAlchemy ORM Models & Schema Protection
│   │   ├── radius.py          # 9 bảng chuẩn FreeRADIUS (radcheck, radacct, nas, ...)
│   │   ├── application.py     # 2 bảng quản trị ứng dụng (app_admins, app_users)
│   │   └── verifier.py        # Read-only Schema Verifier (tương thích MariaDB & SQLite)
│   ├── schemas/               # Pydantic Request Validation & Response Serialization
│   │   ├── __init__.py        # Re-export và quản trị schemas
│   │   └── (tương lai)        # Schemas cho Admin, User, Group, Accounting
│   ├── services/              # Pure Business Logic Layer (độc lập với HTTP transport)
│   │   ├── __init__.py        # Service Layer Contract & Re-exports
│   │   ├── base.py            # BaseService nhận Session qua DI
│   │   ├── transaction.py     # Transactional guard (Explicit Top-level Transaction Ownership)
│   │   ├── admin_auth.py      # AdminAuthService cho Dashboard Admin (PBKDF2 310k, DTO an toàn)
│   │   ├── admin_token.py     # AdminTokenService phát hành & kiểm định JWT Access Token (HS256, 30m)
│   │   └── (tương lai)        # UserService, GroupService, AcctService
│   ├── routers/               # API Endpoints & HTTP Request/Response mapping
│   │   ├── health.py          # GET /health, GET /health/database
│   │   └── (tương lai)        # auth.py, users.py, groups.py, accounting.py
│   ├── database.py            # SQLAlchemy Engine singleton, SessionLocal, get_db()
│   ├── main.py                # FastAPI Application instance & router/handler registration
│   ├── radius_auth.py         # Module xác thực trực tiếp FreeRADIUS (PAP qua pyrad2)
│   └── schemas.py             # Schema kế thừa (LoginRequest, LoginResponse)
├── test_core_security.py      # Unit tests nhóm Core & Security (12 tests)
├── test_database_foundation.py# Unit tests nhóm Database Engine & ORM (27 tests)
├── test_app_health.py         # Unit tests nhóm Health Monitoring (9 tests)
├── test_service_foundation.py # Unit tests nhóm Service Layer & Transaction Safety (15 tests)
├── test_exception_handlers.py # Unit tests nhóm Global Exception Handlers (14 tests)
├── test_admin_auth.py         # Unit tests nhóm Admin Authentication Service (15 tests)
└── test_admin_token.py        # Unit tests nhóm Admin Token Service (22 tests)
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

### 5.1. QUY ƯỚC XÁC THỰC DASHBOARD ADMIN (ADMIN AUTHENTICATION)

1. **Tách biệt hoàn toàn với RADIUS Network Authentication**:
   - Dashboard Admin là tài khoản quản trị ứng dụng web lưu tại bảng `app_admins`.
   - Tuyệt đối không sử dụng bảng `radcheck` hoặc giao thức RADIUS (PAP/CHAP) để xác thực Dashboard Admin.
2. **Cơ chế băm mật khẩu**:
   - Sử dụng PBKDF2-HMAC-SHA256 với 310.000 vòng lặp (iterations) và 16 bytes salt từ `app/core/security.py`.
3. **Thao tác chỉ đọc (Read-Only)**:
   - Quá trình xác thực là truy vấn SELECT chỉ đọc qua SQLAlchemy Session tiêm từ ngoài, không gọi `commit()` hay `rollback()`, không dùng `transactional()`.
4. **Bảo vệ dữ liệu nhạy cảm**:
   - Kết quả trả về là DTO `AdminAuthResult` an toàn (chỉ chứa `id`, `username`, `email`, `role`, `is_active`, `created_at`), tuyệt đối không chứa `password` hay `password_hash`.
5. **Phòng vệ Timing Attack & Username Enumeration**:
   - Khi username không tồn tại trong CSDL, `AdminAuthService` tự động chạy hàm `verify_password` giả lập với `DUMMY_PASSWORD_HASH` (cùng 310.000 vòng lặp) để đồng nhất thời gian phản hồi với trường hợp username tồn tại, ngăn chặn kẻ tấn công dò quét danh tính quản trị viên.
   - Thống nhất cùng một ngoại lệ `UnauthorizedError("Tên đăng nhập hoặc mật khẩu không chính xác.", code="INVALID_CREDENTIALS")` cho cả hai trường hợp sai username và sai mật khẩu.
6. **Tài khoản bị vô hiệu hóa (`is_active=False`)**:
   - Bị từ chối truy cập với `ForbiddenError("Tài khoản quản trị đã bị vô hiệu hóa. Vui lòng liên hệ quản trị viên cấp cao.", code="ACCOUNT_INACTIVE")` (HTTP 403).

---

### 5.2. QUY ƯỚC JWT AUTHENTICATION CHO DASHBOARD ADMIN (JWT TOKEN FOUNDATION)

1. **Vị trí và Phân tầng**:
   - Triển khai tại `backend/app/services/admin_token.py` thông qua `AdminTokenService` và `AdminTokenClaims`.
   - Nằm ở tầng Service Layer, tái sử dụng các hàm mật mã chuẩn từ `app/core/security.py` (PyJWT v2.15+).
   - Tuyệt đối độc lập với CSDL: Không tạo Engine, Session, hoặc kết nối database trong Token Service.
2. **Cơ chế Thuật toán & Thời hạn**:
   - Sử dụng chuẩn ký số **HS256** (HMAC với SHA-256).
   - Thời hạn chuẩn của Access Token: **30 phút** (cấu hình qua `settings.ACCESS_TOKEN_EXPIRE_MINUTES`).
   - Khóa bí mật ký token: lấy từ `settings.JWT_SECRET_KEY` (hoặc inject secret key tùy chọn cho testing).
3. **Cấu trúc Claims tối thiểu và an toàn**:
   - `sub`: ID định danh duy nhất của Admin (chuỗi string, ví dụ `"42"`).
   - `role`: Vai trò của Admin (ví dụ `"superadmin"`, `"it_admin"`).
   - `type`: Bắt buộc là `"access"` để phân biệt Access Token với các token chức năng khác.
   - `iat`: Thời điểm phát hành (UNIX epoch integer).
   - `exp`: Thời điểm hết hạn (UNIX epoch integer, `exp - iat = 1800`).
   - **Tuyệt đối cấm**: Không chứa `password`, `password_hash`, DB connection string hay JWT secret. Không đưa email/thông tin cá nhân vào token nếu không có lý do nghiệp vụ.
4. **Quy tắc Kiểm định & Từ chối Token (Verification Rules)**:
   - Từ chối token sai chữ ký, sai định dạng hoặc chuỗi rác $\rightarrow$ `UnauthorizedError(message="...", code="TOKEN_INVALID")` (HTTP 401).
   - Từ chối token hết hạn $\rightarrow$ `UnauthorizedError(message="Token truy cập đã hết hạn...", code="TOKEN_EXPIRED")` (HTTP 401).
   - Từ chối token dùng thuật toán không được phép (`alg=none`, `HS384`, `RS256`,...) $\rightarrow$ `UnauthorizedError(code="TOKEN_INVALID")`.
   - Từ chối token thiếu `sub`, thiếu `role`, hoặc `type != "access"` $\rightarrow$ `UnauthorizedError(code="TOKEN_INVALID")`.
   - Không để lộ thông tin bí mật hay internal traceback khi phát sinh lỗi JWT.
5. **DTO Trả về (`AdminTokenClaims`)**:
   - Kế thừa từ `dict` để tương thích 100% với truy cập dạng từ điển (`claims['sub']`) lẫn thuộc tính (`claims.sub`, `claims.role`, `claims.exp`).

---

## 6. QUY TẮC XỬ LÝ LỖI & ÁNH XẠ HTTP (GLOBAL EXCEPTION HANDLING CONTRACT)

Hệ thống triển khai cơ chế xử lý ngoại lệ tập trung (Centralized Global Exception Handling) tại `backend/app/core/exception_handlers.py`, tự động đăng ký với FastAPI application instance:

1. **Chuẩn hóa cấu trúc JSON Error Response**:
   Mọi lỗi nghiệp vụ và lỗi hệ thống đều trả về cấu trúc JSON thống nhất:
   ```json
   {
     "error": {
       "code": "<ERROR_CODE>",
       "message": "<ERROR_MESSAGE>"
     }
   }
   ```
   - `code`: Chuỗi định danh lỗi ổn định, viết hoa (SCREAMING_SNAKE_CASE), thân thiện và dễ dàng cho Frontend bắt lỗi logic (i18n, hiển thị form error).
   - `message`: Thông điệp lỗi bằng tiếng Việt rõ ràng, phù hợp với nội dung ngoại lệ.
   - Tuyệt đối không trả về stack trace, query SQL, credentials hay chi tiết nhạy cảm trong response.

2. **Bảng ánh xạ Business Exceptions sang HTTP Response**:

   | Business Exception | HTTP Status Code | Default Error Code | Ý nghĩa nghiệp vụ |
   | :--- | :---: | :--- | :--- |
   | `NotFoundError` | **404** Not Found | `RESOURCE_NOT_FOUND` | Không tìm thấy tài nguyên yêu cầu (User, NAS, Session). |
   | `ConflictError` | **409** Conflict | `RESOURCE_CONFLICT` | Trùng lặp dữ liệu (Username đã tồn tại, IP NAS trùng). |
   | `UnauthorizedError` | **401** Unauthorized | `UNAUTHORIZED` | Thiếu hoặc sai lệch token xác thực, token hết hạn. |
   | `ForbiddenError` | **403** Forbidden | `FORBIDDEN` | Đã xác thực nhưng không đủ quyền thực hiện hành động. |
   | `ServiceUnavailableError` | **503** Service Unavailable | `SERVICE_UNAVAILABLE` | Dịch vụ phụ thuộc (FreeRADIUS, MariaDB) không khả dụng. |
   | `ValidationError` | **422** Unprocessable Entity | `VALIDATION_ERROR` | Dữ liệu vi phạm quy tắc kiểm tra logic nghiệp vụ. |

3. **Xử lý vi phạm ranh giới giao dịch (`TransactionAlreadyActiveError`)**:
   - Đây là lỗi vi phạm kiến trúc phân lớp nội bộ (Developer/Architectural Invariant Violation), xảy ra khi Service con tự ý gọi `transactional()` trên Session đang active.
   - Handler `transaction_already_active_handler` lập tức chuyển hóa thành **HTTP 500 Internal Server Error** an toàn:
     ```json
     {
       "error": {
         "code": "INTERNAL_SERVER_ERROR",
         "message": "Đã xảy ra sự cố nội bộ trong quá trình xử lý giao dịch."
       }
     }
     ```
   - Không để lộ chi tiết session hay cấu trúc nội bộ cho client; đồng thời ghi log `logger.error` kèm stack trace phục vụ điều tra lỗi.

4. **Xử lý ngoại lệ không xác định (Unhandled/General Exception)**:
   - Handler `unhandled_exception_handler` bắt toàn bộ `Exception` chưa được phân loại, trả về **HTTP 500** với code `INTERNAL_SERVER_ERROR` và message thân thiện.
   - Ngăn chặn hoàn toàn việc rò rỉ URL CSDL (chứa username/password), SQL trace, hoặc exception traceback ra client.

5. **Bảo tồn cơ chế mặc định của FastAPI**:
   - `HTTPException` và `StarletteHTTPException`: Được re-raise để FastAPI xử lý theo cơ chế chuẩn mặc định (`{"detail": "..."}`), đảm bảo tương thích hoàn toàn với các endpoint hiện hữu (`/auth/login`, `/health/database`) và tài liệu Swagger `/docs`.
   - `RequestValidationError`: Giữ nguyên handler mặc định của FastAPI để trả về chi tiết lỗi cú pháp schema Pydantic (HTTP 422 `{"detail": [...]}`).

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
| **Services** | Contract (`app/services/base.py`, `transaction.py`), `AdminAuthService` (`admin_auth.py`), `AdminTokenService` (`admin_token.py`) | `UserService`, `GroupService`, `RadiusConfigService` |
| **Exception Handling** | `app/core/exceptions.py`, `app/core/exception_handlers.py` | Ánh xạ thêm các exception domain nghiệp vụ nâng cao |
| **Schemas** | Package `app/schemas/`, `LoginRequest`, `LoginResponse` | DTOs cho User CRUD, Admin Login, Session Logs |
