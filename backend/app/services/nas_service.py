from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

try:
    from app.core.exceptions import ConflictError, NotFoundError
    from app.models import Nas
    from app.schemas.nas import NASCreate, NASResponse
    from app.services import BaseService, transactional
except ImportError:
    from core.exceptions import ConflictError, NotFoundError
    from models import Nas
    from schemas.nas import NASCreate, NASResponse
    from services import BaseService, transactional


class NASService(BaseService):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def get_nas_list(self, skip: int = 0, limit: int = 20) -> list[NASResponse]:
        statement = select(Nas).order_by(Nas.id).offset(skip).limit(limit)
        return [
            NASResponse.model_validate(nas)
            for nas in self.db.scalars(statement)
        ]

    def get_nas_by_id(self, nas_id: int) -> NASResponse:
        nas = self.db.get(Nas, nas_id)
        if nas is None:
            raise NotFoundError("Không tìm thấy thiết bị NAS")
        return NASResponse.model_validate(nas)

    def create_nas(self, data: NASCreate) -> NASResponse:
        try:
            with transactional(self.db):
                existing_nas = self.db.scalar(
                    select(Nas).where(Nas.nasname == data.nasname)
                )
                if existing_nas is not None:
                    raise ConflictError("NAS đã tồn tại")

                nas = Nas(
                    nasname=data.nasname,
                    shortname=data.shortname,
                    type=data.type,
                    secret=data.secret,
                )
                self.db.add(nas)
                self.db.flush()
            return NASResponse.model_validate(nas)
        except IntegrityError as exc:
            raise ConflictError("NAS đã tồn tại") from exc
