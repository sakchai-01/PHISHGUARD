from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum
from datetime import datetime, timezone
import enum
from app.db.session import Base

class ReportStatus(str, enum.Enum):
    new = "new"
    reviewing = "reviewing"
    resolved = "resolved"
    rejected = "rejected"

class ReportType(str, enum.Enum):
    phishing_url = "phishing_url"
    fake_page = "fake_page"
    suspicious_post = "suspicious_post"
    other = "other"

class UserReport(Base):
    __tablename__ = "user_reports"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), index=True, nullable=False)
    type = Column(String(50), nullable=False)  # Map to ReportType
    url = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    status = Column(String(50), default=ReportStatus.new.value)
    
    reported_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    reviewer_note = Column(Text, nullable=True)
