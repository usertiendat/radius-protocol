from sqlalchemy import delete, select
from sqlalchemy.orm import Session

try:
    from app.core.exceptions import ConflictError, NotFoundError, ValidationError
    from app.models import RadGroupCheck, RadGroupReply, RadUserGroup
    from app.schemas.group import GroupAttribute, GroupCreate, GroupResponse, GroupUpdate
    from app.services import BaseService, transactional
except ImportError:
    from core.exceptions import ConflictError, NotFoundError, ValidationError
    from models import RadGroupCheck, RadGroupReply, RadUserGroup
    from schemas.group import GroupAttribute, GroupCreate, GroupResponse, GroupUpdate
    from services import BaseService, transactional


class GroupService(BaseService):
    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def get_groups(self) -> list[GroupResponse]:
        groupnames = set(self.db.scalars(select(RadUserGroup.groupname)))
        groupnames.update(self.db.scalars(select(RadGroupCheck.groupname)))
        groupnames.update(self.db.scalars(select(RadGroupReply.groupname)))
        return [self.get_group_by_name(name) for name in sorted(groupnames)]

    def get_group_by_name(self, groupname: str) -> GroupResponse:
        users = list(
            self.db.scalars(
                select(RadUserGroup.username)
                .where(RadUserGroup.groupname == groupname)
                .order_by(RadUserGroup.priority, RadUserGroup.id)
            )
        )
        checks = list(
            self.db.scalars(
                select(RadGroupCheck)
                .where(RadGroupCheck.groupname == groupname)
                .order_by(RadGroupCheck.id)
            )
        )
        replies = list(
            self.db.scalars(
                select(RadGroupReply)
                .where(RadGroupReply.groupname == groupname)
                .order_by(RadGroupReply.id)
            )
        )
        if not (users or checks or replies):
            raise NotFoundError("Không tìm thấy group")
        return GroupResponse(
            groupname=groupname,
            users=users,
            checks=[self._attribute_dto(row) for row in checks],
            replies=[self._attribute_dto(row) for row in replies],
        )

    def create_group(self, data: GroupCreate) -> GroupResponse:
        with transactional(self.db):
            if self._group_exists(data.groupname):
                raise ConflictError("Group đã tồn tại")
            self._replace_group_data(
                data.groupname,
                users=data.users,
                checks=data.checks,
                replies=data.replies,
            )
        return self.get_group_by_name(data.groupname)

    def update_group(
        self, groupname: str, data: GroupUpdate
    ) -> GroupResponse:
        with transactional(self.db):
            current = self.get_group_by_name(groupname)
            users = data.users if "users" in data.model_fields_set else None
            checks = data.checks if "checks" in data.model_fields_set else None
            replies = data.replies if "replies" in data.model_fields_set else None

            final_users = current.users if users is None else users
            final_checks = current.checks if checks is None else checks
            final_replies = current.replies if replies is None else replies
            if not (final_users or final_checks or final_replies):
                raise ValidationError(
                    "Group phải có ít nhất một thành viên hoặc thuộc tính"
                )

            if users is not None:
                self.db.execute(
                    delete(RadUserGroup).where(
                        RadUserGroup.groupname == groupname
                    )
                )
                self._add_users(groupname, users)
            if checks is not None:
                self.db.execute(
                    delete(RadGroupCheck).where(
                        RadGroupCheck.groupname == groupname
                    )
                )
                self._add_attributes(RadGroupCheck, groupname, checks)
            if replies is not None:
                self.db.execute(
                    delete(RadGroupReply).where(
                        RadGroupReply.groupname == groupname
                    )
                )
                self._add_attributes(RadGroupReply, groupname, replies)
        return self.get_group_by_name(groupname)

    def delete_group(self, groupname: str) -> None:
        with transactional(self.db):
            self.get_group_by_name(groupname)
            self.db.execute(
                delete(RadUserGroup).where(RadUserGroup.groupname == groupname)
            )
            self.db.execute(
                delete(RadGroupCheck).where(RadGroupCheck.groupname == groupname)
            )
            self.db.execute(
                delete(RadGroupReply).where(RadGroupReply.groupname == groupname)
            )

    def _group_exists(self, groupname: str) -> bool:
        return any(
            self.db.scalar(select(model.id).where(model.groupname == groupname).limit(1))
            is not None
            for model in (RadUserGroup, RadGroupCheck, RadGroupReply)
        )

    def _replace_group_data(
        self,
        groupname: str,
        *,
        users: list[str],
        checks: list[GroupAttribute],
        replies: list[GroupAttribute],
    ) -> None:
        self._add_users(groupname, users)
        self._add_attributes(RadGroupCheck, groupname, checks)
        self._add_attributes(RadGroupReply, groupname, replies)

    def _add_users(self, groupname: str, usernames: list[str]) -> None:
        self.db.add_all(
            RadUserGroup(username=username, groupname=groupname, priority=1)
            for username in usernames
        )

    def _add_attributes(
        self,
        model: type[RadGroupCheck] | type[RadGroupReply],
        groupname: str,
        attributes: list[GroupAttribute],
    ) -> None:
        self.db.add_all(
            model(
                groupname=groupname,
                attribute=attribute.attribute,
                op=attribute.op,
                value=attribute.value,
            )
            for attribute in attributes
        )

    @staticmethod
    def _attribute_dto(row: RadGroupCheck | RadGroupReply) -> GroupAttribute:
        return GroupAttribute(attribute=row.attribute, op=row.op, value=row.value)
