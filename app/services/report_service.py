"""
report_service.py — MongoDB Atlas
ย้ายจาก SQLAlchemy มาใช้ ReportRepository (Motor MongoDB)
"""
from typing import List, Optional
from app.repositories.report_repo import ReportRepository


class ReportService:
    """Service สำหรับจัดการ User Reports ด้วย MongoDB"""

    def __init__(self):
        self.repo = ReportRepository()

    async def submit_report(self, email: str, report_type: str,
                            url: str = "", description: str = "") -> dict:
        """บันทึกรายงานใหม่จากผู้ใช้ลง MongoDB"""
        return await self.repo.create_report(
            email=email,
            report_type=report_type,
            url=url,
            description=description
        )

    async def get_recent_reports(self, status: Optional[str] = None, limit: int = 50) -> List[dict]:
        """ดึงรายการรายงานล่าสุด (filter by status ได้)"""
        return await self.repo.get_reports(status=status, limit=limit)

    async def review_report(self, report_id: str, status: str,
                            note: Optional[str] = None) -> bool:
        """อัปเดตสถานะรายงาน (resolved / rejected)"""
        return await self.repo.update_status(
            report_id=report_id,
            status=status,
            reviewer_note=note
        )

    async def get_report_by_id(self, report_id: str) -> Optional[dict]:
        """ดึงรายงานเดี่ยวด้วย ID"""
        return await self.repo.get_report_by_id(report_id)

    async def delete_report(self, report_id: str) -> bool:
        """ลบรายงานออกจากฐานข้อมูลถาวร"""
        return await self.repo.delete_report(report_id)
