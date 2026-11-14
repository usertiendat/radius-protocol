"""Read-only accounting and authentication-log queries."""

from datetime import date, datetime, time, timedelta
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models.radius import Nas, RadAcct, RadCheck, RadPostAuth
from app.services.base import BaseService


class AccountingService(BaseService):
    """Business queries for FreeRADIUS accounting and post-auth records."""

    def __init__(self, db: Session) -> None:
        super().__init__(db)

    def list_sessions(self, skip: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(
                RadAcct.radacctid,
                RadAcct.username,
                RadAcct.nasipaddress,
                RadAcct.acctstarttime,
                RadAcct.acctstoptime,
                RadAcct.acctsessiontime,
                RadAcct.acctinputoctets,
                RadAcct.acctoutputoctets,
                RadAcct.acctterminatecause,
            )
            .order_by(RadAcct.acctstarttime.desc())
            .offset(skip)
            .limit(limit)
        ).mappings()
        return [dict(row) for row in rows]

    def get_session(self, session_id: int) -> dict[str, Any] | None:
        row = self.db.execute(
            select(
                RadAcct.radacctid,
                RadAcct.acctsessionid,
                RadAcct.acctuniqueid,
                RadAcct.username,
                RadAcct.realm,
                RadAcct.nasipaddress,
                RadAcct.nasportid,
                RadAcct.nasporttype,
                RadAcct.acctstarttime,
                RadAcct.acctupdatetime,
                RadAcct.acctstoptime,
                RadAcct.acctinterval,
                RadAcct.acctsessiontime,
                RadAcct.acctauthentic,
                RadAcct.connectinfo_start,
                RadAcct.connectinfo_stop,
                RadAcct.acctinputoctets,
                RadAcct.acctoutputoctets,
                RadAcct.calledstationid,
                RadAcct.callingstationid,
                RadAcct.acctterminatecause,
                RadAcct.servicetype,
                RadAcct.framedprotocol,
                RadAcct.framedipaddress,
            ).where(RadAcct.radacctid == session_id)
        ).mappings().first()
        return dict(row) if row is not None else None

    def list_online_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(
                RadAcct.radacctid,
                RadAcct.username,
                RadAcct.nasipaddress,
                RadAcct.framedipaddress,
                RadAcct.acctstarttime,
                RadAcct.acctupdatetime,
                RadAcct.acctsessiontime,
                RadAcct.acctinputoctets,
                RadAcct.acctoutputoctets,
            )
            .where(RadAcct.acctstoptime.is_(None))
            .order_by(RadAcct.acctstarttime.desc())
            .limit(limit)
        ).mappings()
        return [dict(row) for row in rows]

    def get_statistics(self) -> dict[str, int]:
        row = self.db.execute(
            select(
                func.coalesce(
                    func.sum(case((RadAcct.acctstoptime.is_(None), 1), else_=0)), 0
                ).label("active_sessions"),
                func.coalesce(func.sum(RadAcct.acctsessiontime), 0).label(
                    "total_duration"
                ),
                func.coalesce(func.sum(RadAcct.acctinputoctets), 0).label(
                    "total_download_bytes"
                ),
                func.coalesce(func.sum(RadAcct.acctoutputoctets), 0).label(
                    "total_upload_bytes"
                ),
            )
        ).mappings().one()
        return {key: int(value or 0) for key, value in row.items()}

    def get_session_trend(self, days: int = 7) -> list[dict[str, Any]]:
        today = date.today()
        first_day = today - timedelta(days=days - 1)
        start = datetime.combine(first_day, time.min)
        rows = self.db.execute(
            select(
                func.date(RadAcct.acctstarttime).label("day"),
                func.count(RadAcct.radacctid).label("sessions"),
            )
            .where(RadAcct.acctstarttime >= start)
            .group_by(func.date(RadAcct.acctstarttime))
            .order_by(func.date(RadAcct.acctstarttime))
        ).mappings()
        counts = {str(row["day"]): int(row["sessions"]) for row in rows}
        return [
            {"date": (first_day + timedelta(days=index)).isoformat(), "sessions": counts.get(
                (first_day + timedelta(days=index)).isoformat(), 0
            )}
            for index in range(days)
        ]

    def list_auth_logs(self, skip: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(
                RadPostAuth.id,
                RadPostAuth.username,
                RadPostAuth.reply,
                RadPostAuth.authdate,
            )
            .order_by(RadPostAuth.authdate.desc())
            .offset(skip)
            .limit(limit)
        ).mappings()
        return [dict(row) for row in rows]

    def get_dashboard_summary(self) -> dict[str, int]:
        today = date.today()
        total_users = self.db.scalar(select(func.count(func.distinct(RadCheck.username))))
        total_nas = self.db.scalar(select(func.count(Nas.id)))
        active_sessions = self.db.scalar(
            select(func.count(RadAcct.radacctid)).where(RadAcct.acctstoptime.is_(None))
        )
        today_auth = func.date(RadPostAuth.authdate) == today.isoformat()
        success_today = self.db.scalar(
            select(func.count(RadPostAuth.id)).where(
                today_auth, RadPostAuth.reply == "Access-Accept"
            )
        )
        failed_today = self.db.scalar(
            select(func.count(RadPostAuth.id)).where(
                today_auth, RadPostAuth.reply == "Access-Reject"
            )
        )
        return {
            "total_users": int(total_users or 0),
            "total_nas": int(total_nas or 0),
            "active_sessions": int(active_sessions or 0),
            "login_success_today": int(success_today or 0),
            "login_failed_today": int(failed_today or 0),
        }
