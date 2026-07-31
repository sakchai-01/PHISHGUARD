"""
auth_service.py — MongoDB Atlas
ย้ายจาก SQLAlchemy มาใช้ AdminRepository (Motor MongoDB)
"""
import json
import base64
from typing import Optional
from app.repositories.admin_repo import AdminRepository


class AuthService:
    """Service สำหรับ Authentication ด้วย MongoDB"""

    def __init__(self):
        self.repo = AdminRepository()

    def decode_google_email(self, token: str) -> str:
        """ถอดรหัส Google JWT Token เพื่อดึง email"""
        try:
            payload_b64 = token.split('.')[1]
            missing_padding = len(payload_b64) % 4
            if missing_padding:
                payload_b64 += '=' * (4 - missing_padding)
            payload = json.loads(base64.b64decode(payload_b64).decode('utf-8'))
            return payload.get('email', '')
        except Exception:
            return ""

    async def authenticate_google(self, google_token: str) -> Optional[dict]:
        """ยืนยันตัวตนด้วย Google Token (ดึง email แล้วเช็คใน DB)"""
        email = self.decode_google_email(google_token)
        if not email:
            return None
        return await self.repo.get_by_email(email)

    async def authenticate_local(self, email: str, password: str) -> Optional[dict]:
        """ยืนยันตัวตนด้วย Email + Password"""
        return await self.repo.verify_credentials(email, password)

    async def get_current_admin(self, session_email: str) -> Optional[dict]:
        """ดึงข้อมูล Admin จาก session email (cookie)"""
        if not session_email:
            return None
        return await self.repo.get_by_email(session_email)
