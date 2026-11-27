"""
Bộ kiểm thử đơn vị cho GroupService (Quản lý Nhóm và Chính sách phân quyền RADIUS).
Kiểm thử độc lập với SQLite in-memory, không kết nối MariaDB thật.
Kiểm tra các bảng FreeRADIUS: radusergroup, radgroupcheck, radgroupreply.
"""

from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.database import Base
from app.models import RadGroupCheck, RadGroupReply, RadUserGroup
from app.schemas.group import GroupAttribute, GroupCreate, GroupUpdate
from app.services.group_service import GroupService


@pytest.fixture
def db_session():
    """Tạo database SQLite in-memory cô lập với 3 bảng group FreeRADIUS."""
    engine = create_engine("sqlite:///:memory:")
    tables = [
        RadUserGroup.__table__,
        RadGroupCheck.__table__,
        RadGroupReply.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine, tables=tables)
        engine.dispose()


def test_create_group_success(db_session: Session):
    """Tạo nhóm mới thành công với users, checks và replies."""
    service = GroupService(db_session)
    data = GroupCreate(
        groupname="engineering",
        users=["alice", "bob"],
        checks=[GroupAttribute(attribute="Auth-Type", op=":=", value="PAP")],
        replies=[GroupAttribute(attribute="Session-Timeout", op=":=", value="3600")],
    )
    group = service.create_group(data)

    assert group.groupname == "engineering"
    assert sorted(group.users) == ["alice", "bob"]
    assert len(group.checks) == 1
    assert group.checks[0].attribute == "Auth-Type"
    assert len(group.replies) == 1
    assert group.replies[0].attribute == "Session-Timeout"

    # Kiểm tra trực tiếp bảng CSDL
    user_groups = list(db_session.scalars(select(RadUserGroup).where(RadUserGroup.groupname == "engineering")))
    assert len(user_groups) == 2
    assert {ug.username for ug in user_groups} == {"alice", "bob"}


def test_create_group_duplicate_raises_conflict(db_session: Session):
    """Tạo nhóm đã tồn tại ném ConflictError."""
    service = GroupService(db_session)
    data = GroupCreate(
        groupname="marketing",
        users=["charlie"],
    )
    service.create_group(data)

    with pytest.raises(ConflictError, match="Group đã tồn tại"):
        service.create_group(data)


def test_get_groups_returns_all_groups(db_session: Session):
    """Lấy danh sách tất cả các nhóm hiện có."""
    service = GroupService(db_session)
    service.create_group(GroupCreate(groupname="group_a", users=["user1"]))
    service.create_group(GroupCreate(groupname="group_b", users=["user2"]))

    groups = service.get_groups()
    names = [g.groupname for g in groups]
    assert "group_a" in names
    assert "group_b" in names


def test_ensure_default_groups_normalizes_role_attributes_idempotently(
    db_session: Session,
):
    service = GroupService(db_session)
    service.create_group(
        GroupCreate(
            groupname="Guest",
            users=["guest_user"],
            replies=[
                GroupAttribute(
                    attribute="Filter-Id",
                    op=":=",
                    value="stale-policy",
                ),
                GroupAttribute(
                    attribute="Reply-Message",
                    op=":=",
                    value="Welcome",
                ),
            ],
        )
    )

    groups = service.ensure_default_groups()
    service.ensure_default_groups()

    by_name = {group.groupname: group for group in groups}
    guest_replies = {
        attribute.attribute: attribute.value
        for attribute in by_name["Guest"].replies
    }
    assert guest_replies == {
        "Filter-Id": "Guest",
        "Session-Timeout": "3600",
        "Reply-Message": "Welcome",
    }
    assert {attribute.attribute: attribute.value for attribute in by_name["Admin"].replies} == {
        "Filter-Id": "Admin",
        "Session-Timeout": "28800",
    }
    assert {attribute.attribute: attribute.value for attribute in by_name["Employee"].replies} == {
        "Filter-Id": "Employee",
        "Session-Timeout": "28800",
    }
    refreshed_guest = service.get_group_by_name("Guest")
    assert len(
        [attribute for attribute in refreshed_guest.replies if attribute.attribute == "Filter-Id"]
    ) == 1


def test_get_group_by_name_success(db_session: Session):
    """Lấy thông tin chi tiết một nhóm theo tên."""
    service = GroupService(db_session)
    service.create_group(
        GroupCreate(
            groupname="finance",
            users=["dave"],
            replies=[GroupAttribute(attribute="Reply-Message", op=":=", value="Welcome Finance")],
        )
    )

    group = service.get_group_by_name("finance")
    assert group.groupname == "finance"
    assert group.users == ["dave"]
    assert group.replies[0].value == "Welcome Finance"


def test_get_group_by_name_not_found(db_session: Session):
    """Lấy nhóm không tồn tại ném NotFoundError."""
    service = GroupService(db_session)
    with pytest.raises(NotFoundError, match="Không tìm thấy group"):
        service.get_group_by_name("non_existent_group")


def test_update_group_success(db_session: Session):
    """Cập nhật thành viên và thuộc tính của nhóm."""
    service = GroupService(db_session)
    service.create_group(
        GroupCreate(
            groupname="it_ops",
            users=["eve"],
            checks=[GroupAttribute(attribute="Auth-Type", op=":=", value="PAP")],
        )
    )

    updated = service.update_group(
        "it_ops",
        GroupUpdate(
            users=["eve", "frank"],
            replies=[GroupAttribute(attribute="Session-Timeout", op=":=", value="7200")],
        ),
    )

    assert sorted(updated.users) == ["eve", "frank"]
    assert len(updated.replies) == 1
    assert updated.replies[0].value == "7200"


def test_update_group_not_found(db_session: Session):
    """Cập nhật nhóm không tồn tại ném NotFoundError."""
    service = GroupService(db_session)
    with pytest.raises(NotFoundError, match="Không tìm thấy group"):
        service.update_group("ghost_group", GroupUpdate(users=["ghost"]))


def test_update_group_empty_raises_validation_error(db_session: Session):
    """Cập nhật xóa hết cả thành viên và thuộc tính ném ValidationError."""
    service = GroupService(db_session)
    service.create_group(GroupCreate(groupname="temp_group", users=["temp_user"]))

    with pytest.raises(ValidationError, match="Group phải có ít nhất một thành viên hoặc thuộc tính"):
        service.update_group("temp_group", GroupUpdate(users=[], checks=[], replies=[]))


def test_delete_group_success(db_session: Session):
    """Xóa nhóm và dọn dẹp toàn bộ dữ liệu trong cả 3 bảng."""
    service = GroupService(db_session)
    service.create_group(
        GroupCreate(
            groupname="devs",
            users=["dev1"],
            checks=[GroupAttribute(attribute="Auth-Type", op=":=", value="PAP")],
            replies=[GroupAttribute(attribute="Framed-Protocol", op=":=", value="PPP")],
        )
    )

    service.delete_group("devs")

    # Kiểm tra group không còn tồn tại
    with pytest.raises(NotFoundError):
        service.get_group_by_name("devs")

    # Kiểm tra dữ liệu trong cả 3 bảng đã bị xóa sạch
    assert list(db_session.scalars(select(RadUserGroup).where(RadUserGroup.groupname == "devs"))) == []
    assert list(db_session.scalars(select(RadGroupCheck).where(RadGroupCheck.groupname == "devs"))) == []
    assert list(db_session.scalars(select(RadGroupReply).where(RadGroupReply.groupname == "devs"))) == []


def test_delete_group_not_found(db_session: Session):
    """Xóa nhóm không tồn tại ném NotFoundError."""
    service = GroupService(db_session)
    with pytest.raises(NotFoundError, match="Không tìm thấy group"):
        service.delete_group("non_existent_group")
