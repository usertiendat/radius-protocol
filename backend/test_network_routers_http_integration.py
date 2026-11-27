"""HTTP integration coverage for authenticated users, groups, and NAS APIs."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Generator

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.admin_dependencies import get_admin_token_service
from app.core.dependencies import get_write_db
from app.core.security import hash_password
from app.database import Base, get_db
from app.main import app
from app.models import AppAdmin, Nas
from app.services.admin_token import AdminTokenService

TEST_SECRET_KEY = "test-jwt-secret-key-32-chars-long-for-safe-unit-testing"


class ASGIHttpClient:
    def __init__(self) -> None:
        self.transport = httpx.ASGITransport(app=app)

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        async def send_request() -> httpx.Response:
            async with httpx.AsyncClient(
                transport=self.transport,
                base_url="http://testserver",
            ) as client:
                return await client.request(method, url, **kwargs)

        return asyncio.run(send_request())

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)


@pytest.fixture
def session_factory(tmp_path) -> Generator:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'network-routers.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        db.add(
            AppAdmin(
                username="router_admin",
                password_hash=hash_password("RouterAdminPass123!"),
                email="router-admin@example.test",
                role="it_admin",
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )
        db.commit()
    try:
        yield factory
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def token_service() -> AdminTokenService:
    return AdminTokenService(secret_key=TEST_SECRET_KEY)


@pytest.fixture
def client(session_factory, token_service: AdminTokenService) -> Generator[ASGIHttpClient, None, None]:
    previous_overrides = dict(app.dependency_overrides)

    def override_read_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    def override_write_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_read_db
    app.dependency_overrides[get_write_db] = override_write_db
    app.dependency_overrides[get_admin_token_service] = lambda: token_service
    try:
        yield ASGIHttpClient()
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous_overrides)


def _authorization(
    session_factory,
    token_service: AdminTokenService,
) -> dict[str, str]:
    with session_factory() as db:
        admin = db.query(AppAdmin).filter_by(username="router_admin").one()
        token = token_service.create_access_token(admin)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize(
    "path",
    ["/api/v1/users", "/api/v1/groups", "/api/v1/nas"],
)
def test_router_collections_require_admin_authentication(
    client: ASGIHttpClient,
    path: str,
):
    response = client.get(path)

    assert response.status_code == 401


def test_users_groups_and_nas_crud_over_http(
    client: ASGIHttpClient,
    session_factory,
    token_service: AdminTokenService,
):
    headers = _authorization(session_factory, token_service)

    user_response = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "http_user",
            "password": "HttpUserSecret123!",
            "fullname": "HTTP User",
            "email": "http-user@example.test",
        },
    )
    assert user_response.status_code == 201
    assert "password" not in user_response.json()
    assert client.get("/api/v1/users/http_user", headers=headers).status_code == 200
    assert client.put(
        "/api/v1/users/http_user",
        headers=headers,
        json={"fullname": "Updated HTTP User"},
    ).json()["fullname"] == "Updated HTTP User"
    assert client.delete("/api/v1/users/http_user", headers=headers).status_code == 204

    group_response = client.post(
        "/api/v1/groups",
        headers=headers,
        json={
            "groupname": "http_group",
            "users": ["http_member"],
            "checks": [],
            "replies": [
                {"attribute": "Filter-Id", "op": ":=", "value": "http_group"}
            ],
        },
    )
    assert group_response.status_code == 201
    assert client.get("/api/v1/groups/http_group", headers=headers).status_code == 200
    assert client.put(
        "/api/v1/groups/http_group",
        headers=headers,
        json={"users": ["updated_member"]},
    ).json()["users"] == ["updated_member"]
    assert client.delete("/api/v1/groups/http_group", headers=headers).status_code == 204

    nas_response = client.post(
        "/api/v1/nas",
        headers=headers,
        json={
            "nasname": "192.0.2.80",
            "shortname": "http-router",
            "type": "other",
            "secret": "NAS-HTTP-PRIVATE-SECRET",
        },
    )
    assert nas_response.status_code == 201
    assert "secret" not in nas_response.json()
    assert "NAS-HTTP-PRIVATE-SECRET" not in nas_response.text
    nas_id = nas_response.json()["id"]

    assert client.get(f"/api/v1/nas/{nas_id}", headers=headers).status_code == 200
    updated_nas = client.put(
        f"/api/v1/nas/{nas_id}",
        headers=headers,
        json={"secret": "NAS-ROTATED-PRIVATE-SECRET", "shortname": "updated-router"},
    )
    assert updated_nas.status_code == 200
    assert "secret" not in updated_nas.json()
    assert "NAS-ROTATED-PRIVATE-SECRET" not in updated_nas.text
    with session_factory() as db:
        nas = db.query(Nas).filter_by(id=nas_id).one()
        assert nas.secret == "NAS-ROTATED-PRIVATE-SECRET"

    assert client.delete(f"/api/v1/nas/{nas_id}", headers=headers).status_code == 204
    assert client.get(f"/api/v1/nas/{nas_id}", headers=headers).status_code == 404


def test_auditor_can_read_but_cannot_write_nas(
    client: ASGIHttpClient,
    session_factory,
    token_service: AdminTokenService,
):
    with session_factory() as db:
        admin = db.query(AppAdmin).filter_by(username="router_admin").one()
        admin.role = "auditor"
        db.commit()
    headers = _authorization(session_factory, token_service)

    assert client.get("/api/v1/nas", headers=headers).status_code == 200
    assert client.post(
        "/api/v1/nas",
        headers=headers,
        json={"nasname": "192.0.2.81", "secret": "denied-secret"},
    ).status_code == 403
