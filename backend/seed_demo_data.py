"""Create reusable sample RADIUS users and role groups in the configured database."""

from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError
from app.database import SessionLocal
from app.schemas.group import GroupUpdate
from app.schemas.user import UserCreate
from app.services.group_service import GroupService
from app.services.user_service import UserService

DEMO_USERS = (
    ("demo_admin", "DemoAdminPass123!", "Demo Admin", "Admin"),
    ("demo_employee", "DemoEmployeePass123!", "Demo Employee", "Employee"),
    ("demo_guest", "DemoGuestPass123!", "Demo Guest", "Guest"),
)


def seed_demo_data(db: Session) -> None:
    user_service = UserService(db)
    for username, password, fullname, _ in DEMO_USERS:
        try:
            user_service.create_user(
                UserCreate(
                    username=username,
                    password=password,
                    fullname=fullname,
                    email=f"{username}@example.test",
                )
            )
        except ConflictError:
            pass

    group_service = GroupService(db)
    group_service.ensure_default_groups()
    for username, _, _, groupname in DEMO_USERS:
        group = group_service.get_group_by_name(groupname)
        if username not in group.users:
            group_service.update_group(
                groupname,
                GroupUpdate(users=[*group.users, username]),
            )

    print("Demo users and Admin/Employee/Guest RADIUS groups are ready.")


def main() -> None:
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()


if __name__ == "__main__":
    main()
