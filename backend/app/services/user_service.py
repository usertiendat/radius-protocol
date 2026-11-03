from fastapi import HTTPException
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas


def _commit(db: Session, detail: str) -> None:
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=detail) from exc


def _get_user_or_404(db: Session, username: str) -> models.AppUser:
    user = db.scalar(select(models.AppUser).where(models.AppUser.username == username))
    if user is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy user")
    return user


def get_user(db: Session, username: str) -> models.AppUser:
    return _get_user_or_404(db, username)


def _load_groups(db: Session, group_ids: list[int]) -> list[models.Group]:
    groups = list(db.scalars(select(models.Group).where(models.Group.id.in_(group_ids))))
    if len(groups) != len(set(group_ids)):
        raise HTTPException(status_code=404, detail="Một hoặc nhiều group không tồn tại")
    return groups


def _set_password(db: Session, username: str, password: str) -> None:
    db.execute(
        delete(models.RadCheck).where(
            models.RadCheck.username == username,
            models.RadCheck.attribute == "Cleartext-Password",
        )
    )
    db.add(
        models.RadCheck(
            username=username,
            attribute="Cleartext-Password",
            op=":=",
            value=password,
        )
    )


def create_user(db: Session, payload: schemas.UserCreate) -> models.AppUser:
    user = models.AppUser(
        username=payload.username,
        email=payload.email,
        is_active=payload.is_active,
        groups=_load_groups(db, payload.group_ids),
    )
    db.add(user)
    _set_password(db, payload.username, payload.password)
    _commit(db, "Username đã được sử dụng")
    db.refresh(user)
    return user


def update_user(
    db: Session, username: str, payload: schemas.UserUpdate
) -> models.AppUser:
    user = _get_user_or_404(db, username)
    values = payload.model_dump(exclude_unset=True)
    required_fields = ("username", "is_active", "password", "group_ids")
    if any(field in values and values[field] is None for field in required_fields):
        raise HTTPException(status_code=422, detail="Trường bắt buộc không được là null")

    groups = _load_groups(db, values["group_ids"]) if "group_ids" in values else []
    new_username = values.pop("username", user.username)
    password = values.pop("password", None)
    if new_username != user.username:
        db.execute(
            update(models.RadCheck)
            .where(models.RadCheck.username == user.username)
            .values(username=new_username)
        )
        user.username = new_username
    if password is not None:
        _set_password(db, new_username, password)

    if "group_ids" in values:
        values.pop("group_ids")
        user.groups = groups
    for field, value in values.items():
        setattr(user, field, value)

    _commit(db, "Username đã được sử dụng hoặc dữ liệu không hợp lệ")
    db.refresh(user)
    return user


def delete_user(db: Session, username: str) -> None:
    user = _get_user_or_404(db, username)
    db.execute(
        delete(models.RadCheck).where(models.RadCheck.username == username)
    )
    db.delete(user)
    _commit(db, "Không thể xóa user")
