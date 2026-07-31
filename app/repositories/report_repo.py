"""
report_repo.py — MongoDB Atlas (Motor AsyncIO)
ย้ายจาก SQLAlchemy/SQLite มาใช้ Motor + MongoDB Atlas
Collection: user_reports
"""
from typing import Optional, List
from datetime import datetime, timezone
from bson import ObjectId
from app.core.database import get_database


class ReportRepository:
    """Repository สำหรับ User Reports ใน MongoDB"""

    def _db(self):
        return get_database()

    async def create_report(self, email: str, report_type: str,
                            url: str = "", description: str = "") -> dict:
        """สร้างรายงานใหม่จากผู้ใช้"""
        db = self._db()
        doc = {
            "email": email.strip(),
            "type": report_type,
            "url": url.strip(),
            "description": description,
            "status": "new",
            "reported_at": datetime.now(timezone.utc),
            "reviewed_at": None,
            "reviewer_note": None
        }
        result = await db.user_reports.insert_one(doc)
        doc["_id"] = str(result.inserted_id)
        return doc

    async def get_report_by_id(self, report_id: str) -> Optional[dict]:
        """ค้นหารายงานด้วย ID"""
        db = self._db()
        try:
            doc = await db.user_reports.find_one({"_id": ObjectId(report_id)})
            if doc:
                doc["_id"] = str(doc["_id"])
            return doc
        except Exception:
            return None

    async def get_reports(self, status: Optional[str] = None, limit: int = 50) -> List[dict]:
        """ดึงรายการ report ทั้งหมด (filter by status ได้)"""
        db = self._db()
        query = {"status": status} if status else {}
        cursor = db.user_reports.find(
            query,
            sort=[("reported_at", -1)],
            limit=limit
        )
        docs = await cursor.to_list(length=limit)
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs

    async def update_status(
        self, report_id: str, status: str, reviewer_note: Optional[str] = None
    ) -> bool:
        """อัปเดตสถานะรายงาน (resolved / rejected / reviewing)"""
        db = self._db()
        try:
            update_data: dict = {
                "status": status,
                "reviewed_at": datetime.now(timezone.utc)
            }
            if reviewer_note is not None:
                update_data["reviewer_note"] = reviewer_note

            result = await db.user_reports.update_one(
                {"_id": ObjectId(report_id)},
                {"$set": update_data}
            )
            return result.modified_count > 0
        except Exception:
            return False
