import sqlite3
import os
import sys
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    print("ERROR: MONGODB_URI is not set in .env")
    sys.exit(1)

try:
    client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    # Ping the server to verify connection
    client.admin.command('ping')
    db = client['pdg_db']
    print("Connected to MongoDB Atlas successfully.")
except Exception as e:
    print(f"ERROR connecting to MongoDB: {e}")
    sys.exit(1)

sqlite_db_path = "phishing_db.sqlite"
if not os.path.exists(sqlite_db_path):
    print(f"ERROR: SQLite database file not found at {sqlite_db_path}")
    sys.exit(1)

conn = sqlite3.connect(sqlite_db_path)
cursor = conn.cursor()

from urllib.parse import urlparse

def get_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    except:
        return ""

def migrate_blacklists():
    try:
        # Avoid explicit columns if schema is old
        cursor.execute("SELECT url, threat_level, source, category FROM blacklists")
        rows = cursor.fetchall()
        for url, threat_level, source, category in rows:
            url = url.strip() if url else ""
            if not url: continue
            
            domain = get_domain(url)
            category_lower = (category or "").lower()
            if "safe" in category_lower or "trusted" in category_lower:
                db.safe_urls.update_one({"url": url}, {"$set": {"domain": domain, "category": category, "source": source}}, upsert=True)
            elif threat_level in ["high", "critical"] or "phishing" in category_lower:
                db.phishing_urls.update_one({"url": url}, {"$set": {"domain": domain, "threat_level": "high", "source": source}}, upsert=True)
            else:
                db.fake_urls.update_one({"url": url}, {"$set": {"domain": domain, "description": f"Imported: {category}", "source": source}}, upsert=True)
        print(f"✅ Migrated {len(rows)} entries from SQLite 'blacklists' table.")
    except Exception as e:
        print(f"⚠️ Could not migrate 'blacklists': {e}")

def migrate_phishing_urls():
    try:
        cursor.execute("SELECT url, risk_score, reason FROM phishing_urls")
        rows = cursor.fetchall()
        for url, risk_score, reason in rows:
            url = url.strip() if url else ""
            if not url: continue
            
            domain = get_domain(url)
            
            tl = "high" if risk_score and int(risk_score) > 70 else "medium"
            db.phishing_urls.update_one({"url": url}, {"$set": {"domain": domain, "threat_level": tl, "source": "scraper", "target_brand": "Unknown"}}, upsert=True)
        print(f"✅ Migrated {len(rows)} entries from SQLite 'phishing_urls' table.")
    except Exception as e:
        print(f"⚠️ Could not migrate 'phishing_urls': {e}")

def migrate_safelists():
    try:
        cursor.execute("SELECT url, category FROM safelists")
        rows = cursor.fetchall()
        for url, category in rows:
            url = url.strip() if url else ""
            if not url: continue
            
            domain = get_domain(url)
            
            db.safe_urls.update_one({"url": url}, {"$set": {"domain": domain, "category": category, "source": "admin"}}, upsert=True)
        print(f"✅ Migrated {len(rows)} entries from SQLite 'safelists' table.")
    except Exception as e:
        print(f"ℹ️ No 'safelists' table found or error: {e}")

print("--- Starting Migration ---")
migrate_blacklists()
migrate_phishing_urls()
migrate_safelists()
print("--- Migration Finished ---")
