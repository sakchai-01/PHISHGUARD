from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime, timezone
from app.db.session import Base

class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="admin")  # admin, super_admin, moderator
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
