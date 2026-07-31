from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from typing import List

from app.models.audit_log import AuditLog

class AuditRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def log_action(self, admin_email: str, action: str, details: str = "") -> AuditLog:
        log = AuditLog(admin_email=admin_email, action=action, details=details)
        self.session.add(log)
        await self.session.commit()
        return log

    async def get_recent_logs(self, limit: int = 100) -> List[AuditLog]:
        stmt = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

