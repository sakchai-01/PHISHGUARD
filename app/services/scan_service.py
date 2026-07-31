"""
scan_service.py — MongoDB Atlas
ย้ายจาก SQLAlchemy มาใช้ URLRepository (Motor MongoDB)
"""
import asyncio
from typing import Dict, Any
from urllib.parse import urlparse

from app.repositories.url_repo import URLRepository
from app.domain_checker import analyze_domain


class ScanService:
    """Service สำหรับตรวจสอบ URL ด้วย MongoDB + ML/Heuristics"""

    def __init__(self):
        self.repo = URLRepository()

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Pipeline การสแกน URL:
        1. เช็ค Blacklist/Whitelist จาก MongoDB
        2. ถ้าไม่พบ → ใช้ Heuristics + RL ML
        """
        url_clean = url.strip()

        # 1. ค้นหาจาก MongoDB (exact URL)
        record = await self.repo.get_by_url(url_clean)

        # 2. ถ้าไม่พบ URL ตรง → เช็ค Domain
        if not record:
            domain = urlparse(url_clean if "://" in url_clean else "http://" + url_clean).netloc
            if domain:
                record = await self.repo.get_by_domain(domain)

        # 3. พบใน DB → คืนค่าจาก Reputation DB ทันที
        if record:
            col = record.get("collection", "")
            record_type = record.get("record_type", "phishing")
            if record_type == "safe" or col == "safe_urls":
                return {
                    "status": "safe",
                    "site_name": record.get("domain", url_clean),
                    "message": "ตรวจสอบเรียบร้อย",
                    "risk_score": 0,
                    "details": {
                        "threat_level": "Safe",
                        "category": record.get("category", "Whitelist"),
                        "target_brand": None,
                        "official_url": None,
                        "reasons": ["ปลอดภัย (ตรวจสอบจากฐานข้อมูล Whitelist ของระบบ) ✅"]
                    }
                }
            else:
                return {
                    "status": "danger",
                    "site_name": record.get("domain", url_clean),
                    "message": "ตรวจพบสัญญาณอันตราย",
                    "risk_score": 100,
                    "details": {
                        "threat_level": record.get("threat_level", "High"),
                        "category": "Phishing / Scam",
                        "target_brand": record.get("target_brand", "Unknown"),
                        "official_url": None,
                        "reasons": [
                            f"อันตราย! ตรวจพบในฐานข้อมูล Blacklist (Source: {record.get('source', 'DB')}) 🚨"
                        ]
                    }
                }

        # 4. ไม่พบใน DB → Heuristics + ML Analysis
        domain = urlparse(url_clean if "://" in url_clean else "http://" + url_clean).netloc or url_clean
        analysis = await asyncio.to_thread(analyze_domain, domain, url_clean)

        score = analysis.get("score", 0)
        is_safe = score < 50

        return {
            "status": "safe" if is_safe else "danger",
            "site_name": domain,
            "message": "ตรวจสอบเรียบร้อย" if is_safe else "ตรวจพบสัญญาณอันตราย",
            "risk_score": round(score),
            "details": {
                "threat_level": analysis.get("risk", "Low") if is_safe else analysis.get("risk", "High"),
                "category": "Safe" if is_safe else "Phishing / Scam",
                "target_brand": "Unknown",
                "official_url": None,
                "reasons": analysis.get("details", [])
            }
        }
