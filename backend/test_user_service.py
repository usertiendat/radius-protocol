import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.exceptions import ConflictError, NotFoundError
from app.database import Base
from app.models import AppUser, RadCheck, RadUserGroup
from app.schemas.user import UserCreate, UserUpdate
from app.services.user_service import UserService


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    tables = [
        AppUser.__table__,
        RadCheck.__table__,
        RadUserGroup.__table__,
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


def test_create_user_creates_profile_and_radius_password(db_session: Session):
    user = UserService(db_session).create_user(
        UserCreate(
            username="alice",
            password="radius-password",
            fullname="Alice Example",
            email="alice@example.com",
        )
    )

    assert user.username == "alice"
    assert user.full_name == "Alice Example"
    credential = db_session.scalar(
        select(RadCheck).where(
            RadCheck.username == "alice",
            RadCheck.attribute == "Cleartext-Password",
        )
    )
    assert credential is not None
    assert credential.value == "radius-password"


def test_create_user_rejects_duplicate_username(db_session: Session):
    service = UserService(db_session)
    service.create_user(UserCreate(username="alice", password="first"))

    with pytest.raises(ConflictError, match="Username đã tồn tại"):
        service.create_user(UserCreate(username="alice", password="second"))


def test_update_user_changes_profile_and_radius_password(db_session: Session):
    service = UserService(db_session)
    service.create_user(UserCreate(username="alice", password="old-password"))

    updated = service.update_user(
        "alice",
        UserUpdate(
            password="new-password",
            fullname="Alice Updated",
            email="updated@example.com",
        ),
    )

    assert updated.full_name == "Alice Updated"
    assert updated.email == "updated@example.com"
    credentials = list(
        db_session.scalars(
            select(RadCheck).where(
                RadCheck.username == "alice",
                RadCheck.attribute == "Cleartext-Password",
            )
        )
    )
    assert [credential.value for credential in credentials] == ["new-password"]


def test_delete_user_removes_profile_password_and_group_membership(
    db_session: Session,
):
    service = UserService(db_session)
    service.create_user(UserCreate(username="alice", password="radius-password"))
    db_session.add(
        RadUserGroup(username="alice", groupname="staff", priority=1)
    )
    db_session.commit()

    service.delete_user("alice")

    assert db_session.scalar(
        select(AppUser).where(AppUser.username == "alice")
    ) is None
    assert db_session.scalar(
        select(RadCheck).where(RadCheck.username == "alice")
    ) is None
    assert db_session.scalar(
        select(RadUserGroup).where(RadUserGroup.username == "alice")
    ) is None


def test_user_lookup_raises_not_found(db_session: Session):
    with pytest.raises(NotFoundError):
        UserService(db_session).get_user_by_username("missing")


def test_user_list_applies_pagination(db_session: Session):
    service = UserService(db_session)
    for username in ("alice", "bob", "charlie"):
        service.create_user(UserCreate(username=username, password="password"))

    users = service.get_users(skip=1, limit=1)

    assert [user.username for user in users] == ["bob"]
