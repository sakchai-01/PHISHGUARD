"""
url_repo.py — MongoDB Atlas (Motor AsyncIO)
ย้ายจาก SQLAlchemy/SQLite มาใช้ Motor + MongoDB Atlas
Collections: phishing_urls, safe_urls, fake_urls
"""
from typing import Optional, List
from datetime import datetime, timezone
from urllib.parse import urlparse
from app.core.database import get_database


class URLRepository:
    """Repository สำหรับ URL Blacklist/Whitelist ใน MongoDB"""

    def _db(self):
        return get_database()

    def _extract_domain(self, url: str) -> str:
        parsed = urlparse(url if "://" in url else "http://" + url)
        return parsed.netloc or parsed.path.split("/")[0]

    # ─────────────────────────────────────────────
    # READ: ค้นหา URL จากทุก collection
    # ─────────────────────────────────────────────

    async def get_by_url(self, url: str) -> Optional[dict]:
        """ค้นหา URL ในทุก collection (phishing, safe, fake)"""
        db = self._db()
        url_clean = url.strip()
        for col_name in ("phishing_urls", "safe_urls", "fake_urls"):
            doc = await db[col_name].find_one({"url": url_clean})
            if doc:
                doc["_id"] = str(doc["_id"])
                doc["collection"] = col_name
                # normalize: record_type
                doc["record_type"] = "safe" if col_name == "safe_urls" else "phishing"
                return doc
        return None

    async def get_by_domain(self, domain: str) -> Optional[dict]:
        """ค้นหาด้วยชื่อ Domain"""
        db = self._db()
        domain_clean = domain.strip()
        for col_name in ("phishing_urls", "safe_urls", "fake_urls"):
            doc = await db[col_name].find_one({"domain": domain_clean})
            if doc:
                doc["_id"] = str(doc["_id"])
                doc["collection"] = col_name
                doc["record_type"] = "safe" if col_name == "safe_urls" else "phishing"
                return doc
        return None

    # ─────────────────────────────────────────────
    # WRITE: เพิ่ม URL ลง collection ที่ถูกต้อง
    # ─────────────────────────────────────────────

    async def add_phishing(
        self, url: str, threat_level: str = "high",
        target_brand: str = "", source: str = "admin"
    ) -> bool:
        """เพิ่ม URL เข้า phishing_urls"""
        db = self._db()
        try:
            await db.phishing_urls.update_one(
                {"url": url.strip()},
                {"$set": {
                    "url": url.strip(),
                    "domain": self._extract_domain(url),
                    "threat_level": threat_level,
                    "target_brand": target_brand,
                    "source": source,
                    "added_at": datetime.now(timezone.utc)
                }},
                upsert=True
            )
            return True
        except Exception:
            return False

    async def add_safe(
        self, url: str, category: str = "Approved by Admin", source: str = "admin"
    ) -> bool:
        """เพิ่ม URL เข้า safe_urls"""
        db = self._db()
        try:
            await db.safe_urls.update_one(
                {"url": url.strip()},
                {"$set": {
                    "url": url.strip(),
                    "domain": self._extract_domain(url),
                    "category": category,
                    "source": source,
                    "added_at": datetime.now(timezone.utc)
                }},
                upsert=True
            )
            return True
        except Exception:
            return False

    async def add_fake(
        self, url: str, description: str = "", source: str = "admin"
    ) -> bool:
        """เพิ่ม URL เข้า fake_urls"""
        db = self._db()
        try:
            await db.fake_urls.update_one(
                {"url": url.strip()},
                {"$set": {
                    "url": url.strip(),
                    "domain": self._extract_domain(url),
                    "description": description,
                    "source": source,
                    "added_at": datetime.now(timezone.utc)
                }},
                upsert=True
            )
            return True
        except Exception:
            return False

    async def get_phishing_list(self, limit: int = 100) -> List[dict]:
        """ดึงรายการ phishing URLs"""
        db = self._db()
        cursor = db.phishing_urls.find({}, limit=limit)
        docs = await cursor.to_list(length=limit)
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs

    async def get_safe_list(self, limit: int = 100) -> List[dict]:
        """ดึงรายการ safe URLs"""
        db = self._db()
        cursor = db.safe_urls.find({}, limit=limit)
        docs = await cursor.to_list(length=limit)
        for d in docs:
            d["_id"] = str(d["_id"])
        return docs
