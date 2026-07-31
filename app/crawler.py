import asyncio # type: ignore
from datetime import datetime
from app.core.database import add_phishing_url, init_mongodb # type: ignore

# Note: Database initialization is now handled globally in main.py via app.core.database.init_db()

async def save_to_db(url: str, domain: str, risk_score: int, reason: str = ""):
    """Save a crawled URL to the MongoDB phishing_urls collection."""
    # Convert risk_score to threat_level string for consistency with app.core.database
    threat_level = "low"
    if risk_score >= 70:
        threat_level = "high"
    elif risk_score >= 40:
        threat_level = "medium"

    ok = await add_phishing_url(
        url=url,
        domain=domain,
        threat_level=threat_level,
        target_brand="Unknown",
        source="crawler"
    )
    if ok:
        print(f"[CRAWLER] Saved to MongoDB: {url} (Score: {risk_score})")
    else:
        print(f"[CRAWLER] URL already exists or error saving: {url}")
