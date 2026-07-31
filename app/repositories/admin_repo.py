"""
admin_repo.py — MongoDB Atlas (Motor AsyncIO)
ย้ายจาก SQLAlchemy/SQLite มาใช้ Motor + MongoDB Atlas ทั้งหมด
"""
from typing import Optional, List
from datetime import datetime, timezone
from app.core.database import get_database
from app.core.security import get_password_hash, verify_password


class AdminRepository:
    """Repository สำหรับจัดการข้อมูล Admin ใน MongoDB (collection: admins)"""

    def _db(self):
        return get_database()

    async def get_by_email(self, email: str) -> Optional[dict]:
        """ค้นหา Admin ด้วย Email"""
        db = self._db()
        doc = await db.admins.find_one({"email": email.strip()})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def get_by_username(self, username: str) -> Optional[dict]:
        """ค้นหา Admin ด้วย Username"""
        db = self._db()
        doc = await db.admins.find_one({"username": username.strip()})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    async def create_admin(self, email: str, username: str, password: str, role: str = "admin") -> bool:
        """สร้าง Admin ใหม่"""
        db = self._db()
        try:
            await db.admins.insert_one({
                "email": email.strip(),
                "username": username.strip(),
                "password": get_password_hash(password),
                "role": role,
                "created_at": datetime.now(timezone.utc)
            })
            return True
        except Exception:
            return False

    async def list_admins(self) -> List[dict]:
        """ดึงรายชื่อ Admin ทั้งหมด (ไม่รวม password)"""
        db = self._db()
        cursor = db.admins.find({}, {"password": 0})
        docs = await cursor.to_list(length=100)
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs

    async def delete_admin(self, email: str) -> bool:
        """ลบ Admin ด้วย Email"""
        db = self._db()
        result = await db.admins.delete_one({"email": email.strip()})
        return result.deleted_count > 0

    async def update_password(self, email: str, new_password: str) -> bool:
        """เปลี่ยนรหัสผ่าน Admin"""
        db = self._db()
        result = await db.admins.update_one(
            {"email": email.strip()},
            {"$set": {
                "password": get_password_hash(new_password),
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        return result.modified_count > 0

    async def verify_credentials(self, email: str, password: str) -> Optional[dict]:
        """ตรวจสอบ Email + Password สำหรับ Login"""
        admin = await self.get_by_email(email)
        if not admin:
            return None
        stored_hash = admin.get("password", "")
        if not verify_password(password, stored_hash):
            return None
        return admin

    async def log_audit(self, operator_email: str, action: str, detail: str = "") -> None:
        """บันทึก Audit Log สำหรับการกระทำสำคัญของ Admin"""
        db = self._db()
        try:
            await db.audit_logs.insert_one({
                "operator": operator_email,
                "action": action,
                "detail": detail,
                "timestamp": datetime.now(timezone.utc)
            })
        except Exception:
            pass
