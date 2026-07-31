from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime, timezone
from app.db.session import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    admin_email = Column(String(255), index=True, nullable=False)
    action = Column(String(100), nullable=False) # e.g. "approve_report", "delete_admin"
    details = Column(Text, nullable=True) # JSON or descriptive text
    
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
