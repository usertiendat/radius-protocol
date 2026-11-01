import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import URL, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


def _database_url() -> URL | str:
    configured_url = os.getenv("DATABASE_URL")
    if configured_url:
        return configured_url

    database_name = os.getenv("DB_NAME")
    if database_name:
        return URL.create(
            "mysql+pymysql",
            username=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "3306")),
            database=database_name,
            query={"charset": "utf8mb4"},
        )

    return URL.create(
        "sqlite",
        database=str(PROJECT_ROOT / "backend" / "radius.db"),
    )


DATABASE_URL = _database_url()
connect_args = {"check_same_thread": False} if str(DATABASE_URL).startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
