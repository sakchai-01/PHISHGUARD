from pydantic import BaseModel, EmailStr, HttpUrl
from typing import Optional
from datetime import datetime

class ReportCreate(BaseModel):
    email: EmailStr
    type: str
    url: HttpUrl
    description: Optional[str] = None

class ReportResponse(BaseModel):
    id: int
    email: EmailStr
    type: str
    url: HttpUrl
    description: Optional[str] = None
    status: str
    reported_at: datetime
    reviewed_at: Optional[datetime] = None
    reviewer_note: Optional[str] = None

    class Config:
        orm_mode = True
        from_attributes = True
