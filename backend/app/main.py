from typing import TypeVar

from fastapi import Depends, FastAPI, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import models, schemas
from .database import Base, engine, get_db


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="RADIUS Network Access Management",
    description="API quản lý người dùng, nhóm và thiết bị NAS",
    version="0.2.0",
)


def _commit(db: Session, detail: str = "Dữ liệu đã tồn tại hoặc không hợp lệ") -> None:
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=detail) from exc


ModelType = TypeVar("ModelType", bound=Base)


def _get_or_404(
    db: Session, model: type[ModelType], item_id: int, label: str
) -> ModelType:
    item = db.get(model, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy {label}")
    return item


def _load_groups(db: Session, group_ids: list[int]) -> list[models.Group]:
    groups = list(db.scalars(select(models.Group).where(models.Group.id.in_(group_ids))))
    if len(groups) != len(set(group_ids)):
        raise HTTPException(status_code=404, detail="Một hoặc nhiều group không tồn tại")
    return groups


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "radius-backend"}


@app.post("/users", response_model=schemas.UserRead, status_code=status.HTTP_201_CREATED, tags=["Users"])
def create_user(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    user = models.User(
        username=payload.username,
        password_hash=models.User.hash_password(payload.password),
        email=payload.email,
        is_active=payload.is_active,
        groups=_load_groups(db, payload.group_ids),
    )
    db.add(user)
    _commit(db, "Username đã được sử dụng")
    db.refresh(user)
    return user


@app.get("/users", response_model=list[schemas.UserRead], tags=["Users"])
def list_users(db: Session = Depends(get_db)):
    return list(db.scalars(select(models.User).order_by(models.User.id)))


@app.get("/users/{user_id}", response_model=schemas.UserRead, tags=["Users"])
def get_user(user_id: int, db: Session = Depends(get_db)):
    return _get_or_404(db, models.User, user_id, "user")


@app.patch("/users/{user_id}", response_model=schemas.UserRead, tags=["Users"])
def update_user(user_id: int, payload: schemas.UserUpdate, db: Session = Depends(get_db)):
    user = _get_or_404(db, models.User, user_id, "user")
    values = payload.model_dump(exclude_unset=True)
    required_fields = ("username", "is_active", "password", "group_ids")
    if any(field in values and values[field] is None for field in required_fields):
        raise HTTPException(status_code=422, detail="Trường bắt buộc không được là null")
    if "group_ids" in values:
        group_ids = values.pop("group_ids")
        user.groups = _load_groups(db, group_ids)
    if "password" in values:
        password = values.pop("password")
        user.password_hash = models.User.hash_password(password)
    for field, value in values.items():
        setattr(user, field, value)
    _commit(db, "Username đã được sử dụng hoặc dữ liệu không hợp lệ")
    db.refresh(user)
    return user


@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Users"])
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db.delete(_get_or_404(db, models.User, user_id, "user"))
    _commit(db)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/groups", response_model=schemas.GroupRead, status_code=status.HTTP_201_CREATED, tags=["Groups"])
def create_group(payload: schemas.GroupCreate, db: Session = Depends(get_db)):
    group = models.Group(name=payload.name, description=payload.description)
    db.add(group)
    _commit(db, "Tên group đã được sử dụng")
    db.refresh(group)
    return group


@app.get("/groups", response_model=list[schemas.GroupRead], tags=["Groups"])
def list_groups(db: Session = Depends(get_db)):
    return list(db.scalars(select(models.Group).order_by(models.Group.id)))


@app.get("/groups/{group_id}", response_model=schemas.GroupRead, tags=["Groups"])
def get_group(group_id: int, db: Session = Depends(get_db)):
    return _get_or_404(db, models.Group, group_id, "group")


@app.patch("/groups/{group_id}", response_model=schemas.GroupRead, tags=["Groups"])
def update_group(group_id: int, payload: schemas.GroupUpdate, db: Session = Depends(get_db)):
    group = _get_or_404(db, models.Group, group_id, "group")
    values = payload.model_dump(exclude_unset=True)
    if "name" in values and values["name"] is None:
        raise HTTPException(status_code=422, detail="name không được là null")
    for field, value in values.items():
        setattr(group, field, value)
    _commit(db, "Tên group đã được sử dụng hoặc dữ liệu không hợp lệ")
    db.refresh(group)
    return group


@app.delete("/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Groups"])
def delete_group(group_id: int, db: Session = Depends(get_db)):
    db.delete(_get_or_404(db, models.Group, group_id, "group"))
    _commit(db)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/nas", response_model=schemas.NASRead, status_code=status.HTTP_201_CREATED, tags=["NAS"])
def create_nas(payload: schemas.NASCreate, db: Session = Depends(get_db)):
    nas = models.NAS(**payload.model_dump())
    db.add(nas)
    _commit(db, "Địa chỉ IP NAS đã được đăng ký")
    db.refresh(nas)
    return nas


@app.get("/nas", response_model=list[schemas.NASRead], tags=["NAS"])
def list_nas(db: Session = Depends(get_db)):
    return list(db.scalars(select(models.NAS).order_by(models.NAS.id)))


@app.get("/nas/{nas_id}", response_model=schemas.NASRead, tags=["NAS"])
def get_nas(nas_id: int, db: Session = Depends(get_db)):
    return _get_or_404(db, models.NAS, nas_id, "NAS")


@app.patch("/nas/{nas_id}", response_model=schemas.NASRead, tags=["NAS"])
def update_nas(nas_id: int, payload: schemas.NASUpdate, db: Session = Depends(get_db)):
    nas = _get_or_404(db, models.NAS, nas_id, "NAS")
    values = payload.model_dump(exclude_unset=True)
    required_fields = ("name", "ip_address", "shared_secret", "is_active")
    if any(field in values and values[field] is None for field in required_fields):
        raise HTTPException(status_code=422, detail="Các trường NAS không nullable không được là null")
    for field, value in values.items():
        setattr(nas, field, value)
    _commit(db, "Địa chỉ IP NAS đã được đăng ký hoặc dữ liệu không hợp lệ")
    db.refresh(nas)
    return nas


@app.delete("/nas/{nas_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["NAS"])
def delete_nas(nas_id: int, db: Session = Depends(get_db)):
    db.delete(_get_or_404(db, models.NAS, nas_id, "NAS"))
    _commit(db)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
