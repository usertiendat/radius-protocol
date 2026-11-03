from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

try:
    from app.core.exceptions import ConflictError, NotFoundError
    from app.models import AppUser, RadCheck, RadUserGroup
    from app.schemas.user import UserCreate, UserUpdate
    from app.services import BaseService, transactional
except ImportError:
    from core.exceptions import ConflictError, NotFoundError
    from models import AppUser, RadCheck, RadUserGroup
    from schemas.user import UserCreate, UserUpdate
    from services import BaseService, transactional


class UserService(BaseService):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def create_user(self, data: UserCreate) -> AppUser:
        try:
            with transactional(self.db):
                existing_user = self.db.scalar(
                    select(AppUser).where(AppUser.username == data.username)
                )
                if existing_user is not None:
                    raise ConflictError("Username đã tồn tại")

                user = AppUser(
                    username=data.username,
                    full_name=data.fullname,
                    email=data.email,
                )
                self.db.add(user)
                self.db.add(
                    RadCheck(
                        username=data.username,
                        attribute="Cleartext-Password",
                        op=":=",
                        value=data.password,
                    )
                )
                self.db.flush()
            return user
        except IntegrityError as exc:
            raise ConflictError("Username đã tồn tại") from exc

    def get_users(self, skip: int = 0, limit: int = 20) -> list[AppUser]:
        statement = select(AppUser).order_by(AppUser.id).offset(skip).limit(limit)
        return list(self.db.scalars(statement))

    def get_user_by_username(self, username: str) -> AppUser:
        user = self.db.scalar(select(AppUser).where(AppUser.username == username))
        if user is None:
            raise NotFoundError("Không tìm thấy user")
        return user

    def update_user(self, username: str, data: UserUpdate) -> AppUser:
        values = data.model_dump(exclude_unset=True)
        try:
            with transactional(self.db):
                user = self.db.scalar(
                    select(AppUser).where(AppUser.username == username)
                )
                if user is None:
                    raise NotFoundError("Không tìm thấy user")

                if "fullname" in values:
                    user.full_name = values.pop("fullname")
                if "email" in values:
                    user.email = values.pop("email")

                password = values.get("password")
                if password is not None:
                    self.db.execute(
                        delete(RadCheck).where(
                            RadCheck.username == username,
                            RadCheck.attribute == "Cleartext-Password",
                        )
                    )
                    self.db.add(
                        RadCheck(
                            username=username,
                            attribute="Cleartext-Password",
                            op=":=",
                            value=password,
                        )
                    )

                self.db.flush()
            return user
        except IntegrityError as exc:
            raise ConflictError("Không thể cập nhật user") from exc

    def delete_user(self, username: str) -> None:
        with transactional(self.db):
            user = self.db.scalar(select(AppUser).where(AppUser.username == username))
            if user is None:
                raise NotFoundError("Không tìm thấy user")

            self.db.execute(delete(RadCheck).where(RadCheck.username == username))
            self.db.execute(
                delete(RadUserGroup).where(RadUserGroup.username == username)
            )
            self.db.delete(user)
