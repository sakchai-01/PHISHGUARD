import whois
from datetime import datetime
from app.utils.network import is_safe_url

def whois_features(domain):
    # SSRF Protection: Ensure domain doesn't resolve to internal IP
    if not is_safe_url(f"http://{domain}"):
        return {"domain_age_days": 0, "registrar": "Blocked (Internal IP) 🚫"}

    try:
        w = whois.whois(domain)
        creation = w.get("creation_date")
        if isinstance(creation, list):
            creation = creation[0]

        age_days = (datetime.utcnow() - creation).days if creation else 0
        return {
            "domain_age_days": age_days,
            "registrar": w.get("registrar") or "Unknown"
        }
    except:
        return {"domain_age_days":0,"registrar":"Unknown"}
