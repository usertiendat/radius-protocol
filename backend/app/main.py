from typing import TypeVar

from fastapi import Depends, FastAPI, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import models, schemas
from .database import Base, engine, get_db
from .services import user_service


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


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "radius-backend"}


@app.post("/users", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED, tags=["Users"])
def create_user(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    return user_service.create_user(db, payload)


@app.get("/users", response_model=list[schemas.UserResponse], tags=["Users"])
def list_users(db: Session = Depends(get_db)):
    return list(db.scalars(select(models.AppUser).order_by(models.AppUser.id)))


@app.get("/users/{username}", response_model=schemas.UserResponse, tags=["Users"])
def get_user(username: str, db: Session = Depends(get_db)):
    return user_service.get_user(db, username)


@app.patch("/users/{username}", response_model=schemas.UserResponse, tags=["Users"])
def update_user(username: str, payload: schemas.UserUpdate, db: Session = Depends(get_db)):
    return user_service.update_user(db, username, payload)


@app.delete("/users/{username}", status_code=status.HTTP_204_NO_CONTENT, tags=["Users"])
def delete_user(username: str, db: Session = Depends(get_db)):
    user_service.delete_user(db, username)
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


@app.post("/nas", response_model=schemas.NASResponse, status_code=status.HTTP_201_CREATED, tags=["NAS"])
def create_nas(payload: schemas.NASCreate, db: Session = Depends(get_db)):
    nas = models.NAS(**payload.model_dump())
    db.add(nas)
    _commit(db, "Địa chỉ IP NAS đã được đăng ký")
    db.refresh(nas)
    return nas


@app.get("/nas", response_model=list[schemas.NASResponse], tags=["NAS"])
def list_nas(db: Session = Depends(get_db)):
    return list(db.scalars(select(models.NAS).order_by(models.NAS.id)))


@app.get("/nas/{nas_id}", response_model=schemas.NASResponse, tags=["NAS"])
def get_nas(nas_id: int, db: Session = Depends(get_db)):
    return _get_or_404(db, models.NAS, nas_id, "NAS")


@app.patch("/nas/{nas_id}", response_model=schemas.NASResponse, tags=["NAS"])
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
