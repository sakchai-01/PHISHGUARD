from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from datetime import datetime, timezone
from app.db.session import Base

class URLRecord(Base):
    """
    Unified model for Whitelist and Blacklist URLs
    Replaces safe_urls, fake_urls, and phishing_urls collections.
    """
    __tablename__ = "url_records"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), index=True, unique=True, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    
    # "safe", "phishing", "fake"
    record_type = Column(String(50), nullable=False) 
    
    threat_level = Column(String(50), nullable=True) # e.g. "high", "medium"
    description = Column(Text, nullable=True)
    source = Column(String(100), default="system")
    
    added_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
