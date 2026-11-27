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
from app.models import Nas
from app.schemas.nas import NASCreate, NASResponse, NASUpdate
from app.services.nas_service import NASService


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Nas.__table__])
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine, tables=[Nas.__table__])
        engine.dispose()


def test_create_nas_persists_secret_but_never_returns_it(db_session: Session):
    response = NASService(db_session).create_nas(
        NASCreate(
            nasname="192.0.2.10",
            shortname="edge-router",
            type="mikrotik",
            secret="private-shared-secret",
        )
    )

    persisted = db_session.scalar(select(Nas).where(Nas.nasname == "192.0.2.10"))
    assert persisted is not None
    assert persisted.secret == "private-shared-secret"
    assert response.nasname == "192.0.2.10"
    assert "secret" not in response.model_dump()
    assert "secret" not in NASResponse.model_fields


def test_nas_queries_do_not_return_secret(db_session: Session):
    NASService(db_session).create_nas(
        NASCreate(nasname="192.0.2.11", secret="private-shared-secret")
    )

    result = NASService(db_session).get_nas_list()

    assert len(result) == 1
    assert result[0].nasname == "192.0.2.11"
    assert "secret" not in result[0].model_dump()


def test_create_nas_rejects_duplicate_nasname(db_session: Session):
    service = NASService(db_session)
    service.create_nas(NASCreate(nasname="192.0.2.12", secret="first-secret"))

    with pytest.raises(ConflictError, match="NAS đã tồn tại"):
        service.create_nas(
            NASCreate(nasname="192.0.2.12", secret="second-secret")
        )


def test_update_nas_changes_secret_without_returning_it(db_session: Session):
    service = NASService(db_session)
    created = service.create_nas(
        NASCreate(nasname="192.0.2.13", secret="initial-secret")
    )

    updated = service.update_nas(
        created.id,
        NASUpdate(nasname="192.0.2.14", secret="replacement-secret"),
    )

    persisted = db_session.get(Nas, created.id)
    assert updated.nasname == "192.0.2.14"
    assert "secret" not in updated.model_dump()
    assert persisted is not None
    assert persisted.secret == "replacement-secret"


def test_update_nas_rejects_duplicate_nasname(db_session: Session):
    service = NASService(db_session)
    first = service.create_nas(
        NASCreate(nasname="192.0.2.15", secret="first-secret")
    )
    service.create_nas(NASCreate(nasname="192.0.2.16", secret="second-secret"))

    with pytest.raises(ConflictError, match="NAS đã tồn tại"):
        service.update_nas(first.id, NASUpdate(nasname="192.0.2.16"))


def test_delete_nas_removes_record_and_missing_id_raises(db_session: Session):
    service = NASService(db_session)
    created = service.create_nas(
        NASCreate(nasname="192.0.2.17", secret="private-secret")
    )

    service.delete_nas(created.id)

    assert db_session.get(Nas, created.id) is None
    with pytest.raises(NotFoundError, match="Không tìm thấy thiết bị NAS"):
        service.delete_nas(created.id)
