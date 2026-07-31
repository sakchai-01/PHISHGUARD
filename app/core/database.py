
from typing import Optional, Any
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING, TEXT
from dotenv import load_dotenv
from bson import ObjectId

load_dotenv()
import os
import aiosqlite
import sqlite3
from datetime import datetime, timezone
from passlib.context import CryptContext

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Define Absolute Path for Database
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(PROJECT_ROOT, "phishing_db.sqlite")

async def get_db_connection():
    """
    Async connection for FastAPI routes
    """
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    return conn

def get_sync_db_connection():
    """
    Sync connection for background threads (Scraper/Crawler)
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

async def init_db():
    """
    Initialize all required tables in one place
    """
    # 1. Table for Blacklists (API/Manual)
    # 2. Table for Phishing URLs (Scraper/Crawler)
    
    # We will consolidate them into a more robust schema or keep both for compatibility but managed here.
    async with aiosqlite.connect(DB_PATH) as conn:
        # Table: blacklists
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS blacklists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                domain TEXT,
                threat_level TEXT,
                source TEXT,
                category TEXT DEFAULT 'Unknown',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table: phishing_urls (for scraper compatibility)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS phishing_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                domain TEXT,
                risk_score INTEGER,
                reason TEXT,
                created_at TEXT
            )
        """)
        
        await conn.commit()

    # Also initialize MongoDB
    try:
        await init_mongodb()
    except Exception as e:
        print(f'[MongoDB Init Error]: {e}')


# ===========================================================================
# MongoDB Integration (from Jennisdatabase)
# ===========================================================================
# from datetime import datetime, timezone
from typing import Optional, Any
from motor.motor_asyncio import AsyncIOMotorClient # type: ignore
from pymongo import ASCENDING, DESCENDING, TEXT # type: ignore
# from dotenv import load_dotenv # type: ignore

# load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "pdg_db")

# ---------------------------------------------------------------------------
# Global client & db (initialised once in init_db / get_database)
# ---------------------------------------------------------------------------
_client: Optional[AsyncIOMotorClient] = None
_db: Optional[Any] = None


def get_database():
    """Return the shared Motor database instance."""
    global _client, _db
    if _db is None:
        _client = AsyncIOMotorClient(MONGODB_URI)
        _db = _client[MONGODB_DB_NAME]
    return _db


async def init_mongodb():
    """
    Initialise the MongoDB database, ensure all collections and indexes exist.
    Called once at application startup.

    Collections
    -----------
    1.  fake_urls               – ลิงก์เว็บปลอม
    2.  phishing_urls           – ลิงก์เว็บ Phishing ทั่วไป
    3.  safe_urls               – ลิงก์เว็บปลอดภัย
    4.  fake_facebook_pages     – เพจ Facebook ปลอม
    5.  facebook_phishing_posts – โพสต์ Facebook Phishing
    6.  safe_facebook_pages     – เพจ Facebook ปลอดภัย
    7.  user_admin_questions    – คำถามที่ผู้ใช้ถาม Admin
    8.  user_reports            – URL และข้อความแจ้งเหตุจากผู้ใช้
    9.  user_sourcecode_reports – Sourcecode ที่ผู้ใช้แจ้งเข้ามา
    """
    db = get_database()

    # ── 1. fake_urls ────────────────────────────────────────────────────────
    await db.fake_urls.create_index([("url", ASCENDING)], unique=True)
    await db.fake_urls.create_index([("domain", ASCENDING)])
    await db.fake_urls.create_index([("added_at", DESCENDING)])

    # ── 2. phishing_urls ────────────────────────────────────────────────────
    await db.phishing_urls.create_index([("url", ASCENDING)], unique=True)
    await db.phishing_urls.create_index([("threat_level", ASCENDING)])
    await db.phishing_urls.create_index([("added_at", DESCENDING)])

    # ── 3. safe_urls ────────────────────────────────────────────────────────
    await db.safe_urls.create_index([("url", ASCENDING)], unique=True)
    await db.safe_urls.create_index([("added_at", DESCENDING)])

    # ── 4. fake_facebook_pages ──────────────────────────────────────────────
    await db.fake_facebook_pages.create_index([("page_url", ASCENDING)], unique=True)
    await db.fake_facebook_pages.create_index([("page_name", TEXT)])
    await db.fake_facebook_pages.create_index([("added_at", DESCENDING)])

    # ── 5. facebook_phishing_posts ──────────────────────────────────────────
    await db.facebook_phishing_posts.create_index([("post_url", ASCENDING)], unique=True)
    await db.facebook_phishing_posts.create_index([("content", TEXT)])
    await db.facebook_phishing_posts.create_index([("added_at", DESCENDING)])

    # ── 6. safe_facebook_pages ──────────────────────────────────────────────
    await db.safe_facebook_pages.create_index([("page_url", ASCENDING)], unique=True)
    await db.safe_facebook_pages.create_index([("page_name", TEXT)])
    await db.safe_facebook_pages.create_index([("added_at", DESCENDING)])

    # ── 7. user_admin_questions ─────────────────────────────────────────────
    await db.user_admin_questions.create_index([("asked_at", DESCENDING)])
    await db.user_admin_questions.create_index([("status", ASCENDING)])

    # ── 8. user_reports ─────────────────────────────────────────────────────
    await db.user_reports.create_index([("reported_at", DESCENDING)])
    await db.user_reports.create_index([("email", ASCENDING)])
    await db.user_reports.create_index([("type", ASCENDING)])
    await db.user_reports.create_index([("url", TEXT)])

    # ── 9. user_sourcecode_reports ──────────────────────────────────────────
    await db.user_sourcecode_reports.create_index([("reported_at", DESCENDING)])
    await db.user_sourcecode_reports.create_index([("language", ASCENDING)])
    await db.user_sourcecode_reports.create_index([("status", ASCENDING)])

    # ── 10. admins ────────────────────────────────────────────────────────
    await db.admins.create_index([("email", ASCENDING)], unique=True)
    await db.admins.create_index([("username", ASCENDING)], unique=True)
    await db.admins.create_index([("role", ASCENDING)])

    print(f"[DB] MongoDB '{MONGODB_DB_NAME}' initialised – all collections & indexes ready.")


# ===========================================================================
# Helper functions – per collection
# ===========================================================================

# ── 1 & 2. URL Blacklists (fake / phishing / safe) ─────────────────────────

async def add_fake_url(url: str, domain: str, description: str = "", source: str = "admin") -> bool:
    """Insert a fake-website URL. Returns True on success, False if duplicate."""
    db = get_database()
    try:
        await db.fake_urls.insert_one({
            "url": url.strip(),
            "domain": domain.strip(),
            "description": description,
            "source": source,
            "added_at": datetime.now(timezone.utc),
        })
        return True
    except Exception:
        return False


async def add_phishing_url(url: str, domain: str, threat_level: str = "medium",
                           target_brand: str = "", source: str = "admin") -> bool:
    """Insert a general phishing URL."""
    db = get_database()
    try:
        await db.phishing_urls.insert_one({
            "url": url.strip(),
            "domain": domain.strip(),
            "threat_level": threat_level,
            "target_brand": target_brand,
            "source": source,
            "added_at": datetime.now(timezone.utc),
        })
        return True
    except Exception:
        return False


async def add_safe_url(url: str, domain: str, category: str = "", source: str = "admin") -> bool:
    """Whitelist a safe URL."""
    db = get_database()
    try:
        await db.safe_urls.insert_one({
            "url": url.strip(),
            "domain": domain.strip(),
            "category": category,
            "source": source,
            "added_at": datetime.now(timezone.utc),
        })
        return True
    except Exception:
        return False


async def search_url_in_all(url: str) -> Optional[dict]:
    """
    Search for a URL across fake_urls, phishing_urls, and safe_urls.
    Returns a dict with 'collection' and 'document', or None.
    """
    try:
        db = get_database()
        for col_name in ("fake_urls", "phishing_urls", "safe_urls"):
            col = db[col_name]
            doc = await col.find_one({"url": url.strip()})
            if doc:
                doc["_id"] = str(doc["_id"])
                return {"collection": col_name, "document": doc}
    except Exception as e:
        print(f"[DB Error] search_url_in_all failed: {e}")
    return None


# ── 4, 5, 6. Facebook Pages / Posts ────────────────────────────────────────

async def add_fake_facebook_page(page_url: str, page_name: str,
                                  impersonates: str = "", evidence: str = "") -> bool:
    db = get_database()
    try:
        await db.fake_facebook_pages.insert_one({
            "page_url": page_url.strip(),
            "page_name": page_name.strip(),
            "impersonates": impersonates,
            "evidence": evidence,
            "verified": False,
            "added_at": datetime.now(timezone.utc),
        })
        return True
    except Exception:
        return False


async def add_facebook_phishing_post(post_url: str, content: str,
                                      phishing_link: str = "", page_name: str = "") -> bool:
    db = get_database()
    try:
        await db.facebook_phishing_posts.insert_one({
            "post_url": post_url.strip(),
            "content": content,
            "phishing_link": phishing_link.strip(),
            "page_name": page_name,
            "added_at": datetime.now(timezone.utc),
        })
        return True
    except Exception:
        return False


async def add_safe_facebook_page(page_url: str, page_name: str,
                                  official_brand: str = "", verified: bool = False) -> bool:
    db = get_database()
    try:
        await db.safe_facebook_pages.insert_one({
            "page_url": page_url.strip(),
            "page_name": page_name.strip(),
            "official_brand": official_brand,
            "verified": verified,
            "added_at": datetime.now(timezone.utc),
        })
        return True
    except Exception:
        return False


# ── 7. user_admin_questions ─────────────────────────────────────────────────

async def save_user_question(email: str, question: str, context_url: str = "") -> str:
    """Save a question submitted by a user to Admin. Returns inserted _id as str."""
    db = get_database()
    result = await db.user_admin_questions.insert_one({
        "email": email.strip(),
        "question": question,
        "context_url": context_url.strip(),
        "status": "pending",       # pending | answered | closed
        "answer": None,
        "asked_at": datetime.now(timezone.utc),
        "answered_at": None,
    })
    return str(result.inserted_id)


async def get_pending_questions(limit: int = 50) -> list:
    db = get_database()
    cursor = db.user_admin_questions.find(
        {"status": "pending"},
        sort=[("asked_at", DESCENDING)],
        limit=limit,
    )
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


# ── 8. user_reports (URL + message alerts) ─────────────────────────────────

async def save_user_report(email: str, report_type: str,
                            url: str = "", description: str = "") -> str:
    """
    Save an incident report from a user.
    report_type: 'phishing_url' | 'fake_page' | 'suspicious_post' | 'other'
    """
    db = get_database()
    result = await db.user_reports.insert_one({
        "email": email.strip(),
        "type": report_type,
        "url": url.strip(),
        "description": description,
        "status": "new",           # new | reviewing | resolved | rejected
        "reported_at": datetime.now(timezone.utc),
        "reviewed_at": None,
        "reviewer_note": None,
    })
    return str(result.inserted_id)


async def get_recent_reports(limit: int = 100) -> list:
    db = get_database()
    cursor = db.user_reports.find(
        {},
        sort=[("reported_at", DESCENDING)],
        limit=limit,
    )
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


# ── 9. user_sourcecode_reports ──────────────────────────────────────────────

async def save_sourcecode_report(email: str, source_code: str,
                                  language: str = "unknown",
                                  description: str = "",
                                  filename: str = "") -> str:
    """Save a source-code snippet reported by a user."""
    db = get_database()
    result = await db.user_sourcecode_reports.insert_one({
        "email": email.strip(),
        "filename": filename,
        "language": language,
        "source_code": source_code,
        "description": description,
        "status": "new",           # new | analyzed | safe | malicious
        "analysis_result": None,
        "reported_at": datetime.now(timezone.utc),
        "analyzed_at": None,
    })
    return str(result.inserted_id)


async def get_sourcecode_reports(status: Optional[str] = None, limit: int = 50) -> list:
    db = get_database()
    query = {"status": status} if status else {}
    cursor = db.user_sourcecode_reports.find(
        query,
        sort=[("reported_at", DESCENDING)],
        limit=limit,
    )
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs


# ── 10. Admin Management & Moderation ──────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

async def get_admin_by_email(email: str) -> Optional[dict]:
    db = get_database()
    return await db.admins.find_one({"email": email.strip()})

async def add_admin(email: str, username: str, password_plain: str, role: str = "admin") -> bool:
    db = get_database()
    try:
        await db.admins.insert_one({
            "email": email.strip(),
            "username": username.strip(),
            "password": hash_password(password_plain),
            "role": role,
            "created_at": datetime.now(timezone.utc)
        })
        return True
    except Exception:
        return False

async def delete_admin(email: str) -> bool:
    db = get_database()
    res = await db.admins.delete_one({"email": email.strip()})
    return res.deleted_count > 0

async def list_admins() -> list:
    db = get_database()
    cursor = db.admins.find({}, {"password": 0}) 
    docs = await cursor.to_list(length=100)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs

async def update_report_status(report_id: str, status: str, reviewer_note: str | None = None) -> bool:
    db = get_database()
    try:
        res = await db.user_reports.update_one(
            {"_id": ObjectId(report_id)},
            {"$set": {
                "status": status,
                "reviewed_at": datetime.now(timezone.utc),
                "reviewer_note": reviewer_note
            }}
        )
        return res.modified_count > 0
    except Exception:
        return False

async def get_report_by_id(report_id: str) -> Optional[dict]:
    db = get_database()
    try:
        doc = await db.user_reports.find_one({"_id": ObjectId(report_id)})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc
    except Exception:
        return None
