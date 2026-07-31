import threading
import time
import logging
import random
import asyncio
from app.crawler import save_to_db
from app.utils.network import is_safe_url

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

# List of targets to monitor (Mocking a threat feed)
TARGET_FEEDS = [
    "http://example.com",
    "http://test-phishing.com",
    "http://secure-login-bank.com",
    "http://account-update-required.net"
]

KEYWORDS = ["login", "password", "bank", "update", "verify", "secure"]

def scraper_cycle():
    """
    A single cycle of phishing analysis.
    Can be called by a scheduler or FastAPI BackgroundTasks.
    """
    target = random.choice(TARGET_FEEDS)
    
    # SSRF Protection
    if not is_safe_url(target):
        logger.warning(f"🚫 Blocked potentially unsafe target: {target}")
        return

    try:
        # Simulated analysis
        risk_score = random.randint(10, 95)
        is_phishing = risk_score > 70
        
        if is_phishing:
            reason = f"Detected suspicious keywords: {random.choice(KEYWORDS)}"
            logger.warning(f"⚠️ DETECTED THREAT: {target} (Score: {risk_score})")
            
            asyncio.run(save_to_db(
                url=target,
                domain=target.split('//')[-1],
                risk_score=risk_score,
                reason=reason
            ))
        else:
            logger.info(f"✅ Clean: {target}")
    except Exception as e:
        logger.error(f"Scraper error: {e}")

def run_scraper_background():
    """
    Run phishing scraper in background thread with a loop
    """
    def scraper_loop():
        while True:
            scraper_cycle()
            time.sleep(60) # Run every minute

    thread = threading.Thread(target=scraper_loop, daemon=True)
    thread.start()
