from pydantic import BaseModel, EmailStr
from typing import Optional

class AdminCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    role: str = "admin"

class AdminResponse(BaseModel):
    id: int
    email: EmailStr
    username: str
    role: str

    class Config:
        orm_mode = True
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
