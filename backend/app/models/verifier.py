"""
Schema Verifier: Kiểm tra tính tương thích và toàn vẹn của CSDL MariaDB.
Cơ chế HOÀN TOÀN CHỈ ĐỌC (READ-ONLY METADATA INSPECTION),
tuyệt đối không thực hiện bất kỳ lệnh DDL nào (không create, không alter, không drop).

Hỗ trợ kiểm tra:
1. Table existence (MISSING).
2. Required columns existence (MISMATCH).
3. SQL Data Types & Column Length (chuẩn hóa theo Type Family, hỗ trợ INTEGER/BIGINT có/không UNSIGNED, BOOLEAN với TINYINT(1)).
4. Nullability & Primary Key constraints.
5. Unique Constraints & Unique Indexes (phân biệt rành mạch, tương thích MariaDB và SQLite).
6. Non-unique Indexes (chỉ kiểm tra các index thực sự khai báo trong ORM).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import Engine, UniqueConstraint, inspect
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.types import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Integer,
    Numeric,
    String,
    Time,
)

from app.models.application import AppAdmin, AppUser
from app.models.radius import (
    Nas,
    NasReload,
    RadAcct,
    RadCheck,
    RadGroupCheck,
    RadGroupReply,
    RadPostAuth,
    RadReply,
    RadUserGroup,
)

# Danh mục 11 bảng mục tiêu của hệ thống
ALL_MODELS: List[type[DeclarativeBase]] = [
    # 9 bảng chuẩn FreeRADIUS
    Nas,
    NasReload,
    RadAcct,
    RadCheck,
    RadGroupCheck,
    RadGroupReply,
    RadPostAuth,
    RadReply,
    RadUserGroup,
    # 2 bảng quản trị ứng dụng
    AppAdmin,
    AppUser,
]


class TableStatus(str, Enum):
    OK = "OK"
    MISSING = "MISSING"
    MISMATCH = "MISMATCH"


@dataclass
class TableVerificationReport:
    """Báo cáo chi tiết cho một bảng cụ thể."""
    table_name: str
    status: TableStatus
    missing_columns: List[str] = field(default_factory=list)
    mismatched_columns: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)


@dataclass
class SchemaVerificationSummary:
    """Báo cáo tổng thể toàn bộ 11 bảng trong CSDL."""
    is_valid: bool
    overall_status: str
    missing_tables: List[str] = field(default_factory=list)
    mismatched_tables: List[str] = field(default_factory=list)
    table_reports: Dict[str, TableVerificationReport] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "overall_status": self.overall_status,
            "missing_tables": self.missing_tables,
            "mismatched_tables": self.mismatched_tables,
            "table_reports": {
                name: {
                    "status": report.status.value,
                    "missing_columns": report.missing_columns,
                    "mismatched_columns": report.mismatched_columns,
                    "details": report.details,
                }
                for name, report in self.table_reports.items()
            },
        }


def _check_column_type(model_type: Any, db_type: Any, col_name: str) -> Optional[str]:
    """
    Kiểm tra tính tương thích giữa kiểu dữ liệu ORM Model và CSDL thực tế.
    - Chuẩn hóa theo họ kiểu (Type Family), không so sánh chuỗi máy móc.
    - Xử lý tương thích hợp lý giữa INTEGER/BIGINT có và không có UNSIGNED.
    - Xử lý tương thích BOOLEAN với TINYINT(1) trên MariaDB / MySQL.
    - Kiểm tra độ dài trường String/VARCHAR nếu cả hai cùng xác định length.
    """
    db_type_name = type(db_type).__name__.upper()
    db_words = set(
        db_type_name.replace("(", " ")
        .replace(")", " ")
        .replace(",", " ")
        .split()
    )

    # 1. String / Text Family
    if isinstance(model_type, String):
        is_db_string = isinstance(db_type, String) or bool(
            db_words & {"VARCHAR", "CHAR", "TEXT", "STRING", "TINYTEXT", "MEDIUMTEXT", "LONGTEXT", "NVARCHAR"}
        )
        if not is_db_string:
            return (
                f"Cột '{col_name}' sai lệch kiểu dữ liệu: "
                f"Model khai báo String, nhưng CSDL là {type(db_type).__name__}."
            )

        model_len = getattr(model_type, "length", None)
        db_len = getattr(db_type, "length", None)
        if model_len is not None and db_len is not None and model_len != db_len:
            return (
                f"Cột '{col_name}' sai lệch độ dài chuỗi: "
                f"Model yêu cầu {model_len}, nhưng CSDL là {db_len}."
            )
        return None

    # 2. Integer / BigInteger Family (bao gồm INT, BIGINT có/không UNSIGNED)
    if isinstance(model_type, (Integer, BigInteger)):
        is_db_int = isinstance(db_type, (Integer, BigInteger)) or bool(
            db_words & {"INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT", "MEDIUMINT", "NUMERIC"}
        )
        if not is_db_int:
            return (
                f"Cột '{col_name}' sai lệch kiểu dữ liệu: "
                f"Model khai báo Integer/BigInteger, nhưng CSDL là {type(db_type).__name__}."
            )
        return None

    # 3. DateTime Family
    if isinstance(model_type, DateTime):
        is_db_datetime = isinstance(db_type, (DateTime, Date, Time)) or bool(
            db_words & {"DATETIME", "TIMESTAMP", "DATE", "TIME"}
        )
        if not is_db_datetime:
            return (
                f"Cột '{col_name}' sai lệch kiểu dữ liệu: "
                f"Model khai báo DateTime, nhưng CSDL là {type(db_type).__name__}."
            )
        return None

    # 4. Boolean Family (MariaDB/MySQL lưu dưới dạng TINYINT(1) hoặc BOOLEAN)
    if isinstance(model_type, Boolean):
        is_db_bool = isinstance(db_type, (Boolean, Integer)) or bool(
            db_words & {"BOOL", "BOOLEAN", "TINYINT", "BIT", "INT", "INTEGER"}
        )
        if not is_db_bool:
            return (
                f"Cột '{col_name}' sai lệch kiểu dữ liệu: "
                f"Model khai báo Boolean, nhưng CSDL là {type(db_type).__name__}."
            )
        return None

    return None


def verify_schema(engine: Engine) -> SchemaVerificationSummary:
    """
    Kiểm tra độc lập toàn bộ schema của 11 bảng trong CSDL hiện tại.

    Quy tắc an toàn:
    - Sử dụng sqlalchemy.inspect() thuần túy (Read-only Metadata Inspection).
    - Không gọi Base.metadata.create_all() hoặc drop_all().
    - Không phát sinh bất kỳ câu lệnh DDL nào (CREATE, ALTER, DROP).
    - Phân biệt rành mạch:
      * MISSING: Bảng hoàn toàn chưa tồn tại.
      * MISMATCH: Bảng đã tồn tại nhưng sai lệch cột, kiểu dữ liệu, độ dài, nullability,
                  khóa chính, Unique Constraint hoặc Index.
      * OK: Bảng tồn tại và khớp hoàn toàn với cấu trúc ORM Model.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    missing_tables: List[str] = []
    mismatched_tables: List[str] = []
    table_reports: Dict[str, TableVerificationReport] = {}

    for model in ALL_MODELS:
        table_name = model.__tablename__

        # 1. Kiểm tra sự tồn tại của bảng (MISSING check)
        if table_name not in existing_tables:
            missing_tables.append(table_name)
            table_reports[table_name] = TableVerificationReport(
                table_name=table_name,
                status=TableStatus.MISSING,
                details=[f"Bảng '{table_name}' chưa tồn tại trong cơ sở dữ liệu."],
            )
            continue

        # 2. Nếu bảng đã tồn tại, kiểm tra chi tiết cấu trúc (MISMATCH check)
        missing_columns: List[str] = []
        mismatched_columns: List[str] = []
        details: List[str] = []

        db_columns_info = inspector.get_columns(table_name)
        db_columns = {col["name"]: col for col in db_columns_info}
        db_pk_info = inspector.get_pk_constraint(table_name)
        db_pks = set(db_pk_info.get("constrained_columns") or [])

        model_columns = {col.name: col for col in model.__table__.columns}
        model_pks = {col.name for col in model.__table__.primary_key.columns}

        # 2.1. Kiểm tra các cột bắt buộc, kiểu dữ liệu, độ dài chuỗi và nullability
        for col_name, model_col in model_columns.items():
            if col_name not in db_columns:
                missing_columns.append(col_name)
                details.append(f"Cột '{col_name}' bị thiếu trong bảng '{table_name}'.")
                continue

            db_col = db_columns[col_name]

            # Kiểm tra kiểu dữ liệu và độ dài String/VARCHAR
            type_error = _check_column_type(model_col.type, db_col["type"], col_name)
            if type_error:
                mismatched_columns.append(col_name)
                details.append(type_error)

            # Kiểm tra tính Nullable (chỉ cảnh báo nếu model NOT NULL nhưng DB cho phép NULL)
            if not model_col.nullable and db_col.get("nullable", True) is True:
                # Nếu không phải primary key (PK mặc định NOT NULL trong RDBMS)
                if col_name not in model_pks:
                    mismatched_columns.append(col_name)
                    details.append(
                        f"Cột '{col_name}' trong model là NOT NULL nhưng trong DB cho phép NULL."
                    )

        # 2.2. Kiểm tra Primary Key
        if model_pks and db_pks != model_pks:
            mismatched_columns.extend(list(model_pks - db_pks))
            details.append(
                f"Khóa chính không khớp cho bảng '{table_name}'. "
                f"Model: {sorted(list(model_pks))}, DB: {sorted(list(db_pks))}."
            )

        # 2.3. Kiểm tra Unique Constraints & Unique Indexes
        # Thu thập các ràng buộc Unique được khai báo trong ORM Model
        model_unique_targets: List[Tuple[str, ...]] = []
        for col in model.__table__.columns:
            if col.unique:
                model_unique_targets.append((col.name,))
        for constraint in model.__table__.constraints:
            if isinstance(constraint, UniqueConstraint):
                cols = tuple(sorted([c.name for c in constraint.columns]))
                if cols and cols not in model_unique_targets:
                    model_unique_targets.append(cols)
        for idx in model.__table__.indexes:
            if idx.unique:
                cols = tuple(sorted([c.name for c in idx.columns]))
                if cols and cols not in model_unique_targets:
                    model_unique_targets.append(cols)

        # Thu thập các ràng buộc Unique thực tế từ CSDL
        # Trên MariaDB: Unique Constraint thường phản ánh qua Unique Index hoặc get_unique_constraints().
        # Trên SQLite: Unique Column/Index phản ánh qua get_indexes() với unique=True/1.
        db_unique_sets: List[Set[str]] = []
        for uq in inspector.get_unique_constraints(table_name):
            col_names = uq.get("column_names") or []
            if col_names:
                db_unique_sets.append(set(col_names))

        db_indexes = inspector.get_indexes(table_name)
        for idx in db_indexes:
            if idx.get("unique"):
                col_names = idx.get("column_names") or []
                if col_names:
                    db_unique_sets.append(set(col_names))

        for target_cols in model_unique_targets:
            target_set = set(target_cols)
            # Ràng buộc Unique được thỏa mãn nếu trùng khớp hoặc là tập con của một Unique Constraint/Index trong DB
            if not any(target_set == db_uq or target_set.issubset(db_uq) for db_uq in db_unique_sets):
                # Ngoại lệ: Nếu target_set chính là Primary Key (PK tự động bảo đảm Unique trong RDBMS)
                if target_set != db_pks:
                    for c in target_cols:
                        if c not in mismatched_columns:
                            mismatched_columns.append(c)
                    details.append(
                        f"Bảng '{table_name}' thiếu ràng buộc Unique (Unique Constraint/Index) cho cột: {list(target_cols)}."
                    )

        # 2.4. Kiểm tra Indexes
        # Thu thập các index cần thiết được khai báo trong ORM Model (không xét PK đơn lẻ vì PK đã tự động có chỉ mục)
        model_index_targets: List[Tuple[str, ...]] = []
        for idx in model.__table__.indexes:
            cols = tuple(c.name for c in idx.columns)
            if len(cols) == 1 and cols[0] in model_pks:
                continue
            if cols not in model_index_targets:
                model_index_targets.append(cols)

        db_index_col_tuples = [
            tuple(idx.get("column_names") or [])
            for idx in db_indexes
        ]

        for target_cols in model_index_targets:
            index_found = any(
                len(db_cols) >= len(target_cols) and db_cols[:len(target_cols)] == target_cols
                for db_cols in db_index_col_tuples
            )
            if not index_found:
                for c in target_cols:
                    if c not in mismatched_columns:
                        mismatched_columns.append(c)
                details.append(
                    f"Bảng '{table_name}' thiếu Index cho cột: {list(target_cols)}."
                )

        # 3. Tổng hợp kết quả cho bảng
        if missing_columns or mismatched_columns:
            mismatched_tables.append(table_name)
            table_reports[table_name] = TableVerificationReport(
                table_name=table_name,
                status=TableStatus.MISMATCH,
                missing_columns=missing_columns,
                mismatched_columns=mismatched_columns,
                details=details,
            )
        else:
            table_reports[table_name] = TableVerificationReport(
                table_name=table_name,
                status=TableStatus.OK,
                details=[f"Bảng '{table_name}' tồn tại và khớp cấu trúc."],
            )

    is_valid = len(missing_tables) == 0 and len(mismatched_tables) == 0
    if is_valid:
        overall_status = "OK"
    elif missing_tables and not mismatched_tables:
        overall_status = "MISSING_TABLES"
    elif mismatched_tables and not missing_tables:
        overall_status = "SCHEMA_MISMATCH"
    else:
        overall_status = "INCOMPLETE_AND_MISMATCHED"

    return SchemaVerificationSummary(
        is_valid=is_valid,
        overall_status=overall_status,
        missing_tables=missing_tables,
        mismatched_tables=mismatched_tables,
        table_reports=table_reports,
    )
