"""
app/domain_checker.py - 3-Layer URL Risk Checker Engine
"""

import re
import math
import time
import concurrent.futures
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs

import tldextract

# Helper function for Levenshtein Distance
def levenshtein_distance(s1: str, s2: str) -> int:
    """คำนวณ Levenshtein Distance ระหว่างข้อความ 2 ข้อความ"""
    try:
        import Levenshtein
        return Levenshtein.distance(s1, s2)
    except Exception:
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]


def calculate_entropy(text: str) -> float:
    """คำนวณ Shannon Entropy เพื่อตรวจจับชื่อโดเมนที่สุ่มสร้างอัตโนมัติ (DGA)"""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


WHOIS_CACHE: Dict[str, int] = {}

def get_domain_age_days(domain: str, timeout: float = 0.05) -> int:
    """
    ดึงอายุโดเมนจาก WHOIS โดยใช้ Cache และ Timeout แบบรวดเร็ว (<10ms target)
    หากเกิน timeout หรือดึงไม่ได้ให้ domain_age = -1 ตามข้อกำหนด
    """
    if not domain or domain in ['localhost', '127.0.0.1']:
        return -1
    
    if domain in WHOIS_CACHE:
        return WHOIS_CACHE[domain]

    def _whois_lookup():
        try:
            import whois
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                import datetime
                if isinstance(creation_date, datetime.datetime):
                    age = (datetime.datetime.now() - creation_date).days
                    return age if age >= 0 else -1
        except Exception:
            pass
        return -1

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_whois_lookup)
            age = future.result(timeout=timeout)
            WHOIS_CACHE[domain] = age
            return age
    except Exception:
        WHOIS_CACHE[domain] = -1
        return -1


# ==========================================
# Layer 1 - Heuristic Rules
# ==========================================
def quick_check(url: str) -> dict:
    """
    Layer 1 - Heuristic Rules Check (<10ms target)
    Returns: {"score": 0-100, "reasons": list[str]}
    """
    try:
        score = 0
        reasons = []
        raw_url = url.lower().strip()
        
        parsed = urlparse(raw_url if '://' in raw_url else 'http://' + raw_url)
        host_only = parsed.netloc.split(':')[0]
        
        try:
            ext = tldextract.extract(raw_url)
            subdomain = ext.subdomain.lower()
            domain_name = ext.domain.lower()
            tld = ext.suffix.lower()
            domain_full = f"{domain_name}.{tld}" if tld else domain_name
        except Exception:
            subdomain = ""
            domain_name = host_only.split('.')[0]
            tld = ""
            domain_full = host_only

        # Rule a: มี @ ใน path = +30 risk
        if '@' in parsed.path or '@' in parsed.netloc:
            score += 30
            reasons.append("พบเครื่องหมาย @ ใน URL Path หรือ Authority")

        # Rule b: ใช้ IP address แทนโดเมน = +40 risk
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_only):
            score += 40
            reasons.append("ใช้ IP Address แทนชื่อโดเมน")

        # Rule c: โดเมนอายุ < 14 วัน จาก WHOIS = +35 risk
        domain_age = get_domain_age_days(domain_full, timeout=0.05)
        if 0 <= domain_age < 14:
            score += 35
            reasons.append(f"อายุโดเมนเพียง {domain_age} วัน (น้อยกว่า 14 วัน)")

        # Rule d: TLD เสี่ยง .tk .ml .ga .cf = +20 risk
        risk_tlds = ['tk', 'ml', 'ga', 'cf']
        if tld in risk_tlds or any(raw_url.endswith('.' + rt) or f'.{rt}/' in raw_url for rt in risk_tlds):
            score += 20
            reasons.append(f"ใช้นามสกุลโดเมนที่มีความเสี่ยงสูง (.{tld if tld else 'risk_tld'})")

        # Rule e: Levenshtein distance < 2 กับแบรนด์ ['kbank','scb','bbl','krungthai','shopee','lazada'] = +50 risk
        target_brands = ['kbank', 'scb', 'bbl', 'krungthai', 'shopee', 'lazada']
        domain_tokens = re.split(r'[-_.]', f"{subdomain}.{domain_name}")
        domain_tokens = [t for t in domain_tokens if t]

        typo_detected = False
        for brand in target_brands:
            for token in domain_tokens:
                dist = levenshtein_distance(token, brand)
                if dist < 2:
                    score += 50
                    reasons.append(f"พบพฤติกรรมเลียนแบบแบรนด์ {brand.upper()}")
                    typo_detected = True
                    break
            if typo_detected:
                break

        # Rule f: Shannon entropy > 4.2 = +25 risk
        entropy_val = calculate_entropy(domain_name)
        if entropy_val > 4.2:
            score += 25
            reasons.append(f"ความสุ่มของชื่อโดเมนสูงผิดปกติ (Entropy: {entropy_val:.2f})")

        score = min(max(int(score), 0), 100)
        return {
            "score": score,
            "reasons": reasons
        }
    except Exception as e:
        return {
            "score": 50,
            "reasons": [f"Quick check error: {str(e)}"]
        }


# ==========================================
# Layer 2 - Feature Extraction
# ==========================================
def extract_features(url: str) -> Dict[str, float]:
    """
    Layer 2 - Feature Extraction (20 features)
    Returns dictionary mapping feature_name -> float value
    """
    try:
        raw_url = url.lower().strip()
        parsed = urlparse(raw_url if '://' in raw_url else 'http://' + raw_url)
        host_only = parsed.netloc.split(':')[0]
        
        try:
            ext = tldextract.extract(raw_url)
            subdomain = ext.subdomain.lower()
            domain_name = ext.domain.lower()
            tld = ext.suffix.lower()
            domain_full = f"{domain_name}.{tld}" if tld else domain_name
        except Exception:
            subdomain = ""
            domain_name = host_only.split('.')[0]
            tld = ""
            domain_full = host_only

        domain_tokens = re.split(r'[-_.]', f"{subdomain}.{domain_name}")
        domain_tokens = [t for t in domain_tokens if t]

        def _min_brand_dist(brand: str) -> float:
            if not domain_tokens:
                return float(len(brand))
            return float(min(levenshtein_distance(t, brand) for t in domain_tokens))

        abnormal_tlds = {'tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'gq', 'work', 'click', 'site', 'online', 'vip', 'cc'}
        shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'goo.gl', 'ow.ly'}

        domain_age = get_domain_age_days(domain_full, timeout=0.05)
        query_params = parse_qs(parsed.query)

        features = {
            "url_length": float(len(raw_url)),
            "domain_length": float(len(domain_name)),
            "num_dots": float(raw_url.count('.')),
            "num_hyphens": float(raw_url.count('-')),
            "num_digits": float(sum(c.isdigit() for c in raw_url)),
            "has_https": 1.0 if raw_url.startswith('https') else 0.0,
            "has_at": 1.0 if '@' in raw_url else 0.0,
            "has_ip": 1.0 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_only) else 0.0,
            "entropy": float(calculate_entropy(domain_name)),
            "domain_age_days": float(domain_age),
            "tld_abnormal": 1.0 if tld in abnormal_tlds else 0.0,
            "brand_distance_kbank": _min_brand_dist('kbank'),
            "brand_distance_scb": _min_brand_dist('scb'),
            "brand_distance_shopee": _min_brand_dist('shopee'),
            "subdomain_length": float(len(subdomain)),
            "path_length": float(len(parsed.path)),
            "has_punycode": 1.0 if 'xn--' in host_only else 0.0,
            "num_params": float(len(query_params)),
            "is_shortened_url": 1.0 if host_only in shorteners else 0.0,
            "favicon_match_brand": 0.0
        }
        return features
    except Exception as e:
        return {
            "url_length": float(len(url)), "domain_length": 10.0, "num_dots": 2.0, "num_hyphens": 0.0, "num_digits": 0.0,
            "has_https": 0.0, "has_at": 0.0, "has_ip": 0.0, "entropy": 3.0, "domain_age_days": -1.0,
            "tld_abnormal": 0.0, "brand_distance_kbank": 5.0, "brand_distance_scb": 5.0, "brand_distance_shopee": 5.0,
            "subdomain_length": 0.0, "path_length": 0.0, "has_punycode": 0.0, "num_params": 0.0,
            "is_shortened_url": 0.0, "favicon_match_brand": 0.0
        }


# ==========================================
# Ensemble Logic - check_url_full
# ==========================================
def check_url_full(url: str) -> dict:
    """
    Ensemble Logic for 3-Layer Phishing Guard
    Step 1: quick_check (If score > 80, return immediately)
    Step 2: If score <= 80, extract_features + pdg_ml.predict_risk
    Final Score = 0.3 * heuristic + 0.7 * ml_score
    Returns: {"final_score": 0-100, "level": "ปลอดภัย|เสี่ยง|อันตราย", "reasons": [...], "response_time_ms": int}
    """
    start_time = time.time()
    try:
        # Step 1: Layer 1 Quick Check
        quick_res = quick_check(url)
        quick_score = quick_res.get("score", 0)
        reasons = list(quick_res.get("reasons", []))

        # Early exit if score > 80
        if quick_score > 80:
            elapsed_ms = int((time.time() - start_time) * 1000)
            return {
                "final_score": float(quick_score),
                "level": "อันตราย",
                "reasons": reasons,
                "response_time_ms": elapsed_ms
            }

        # Step 2: Layer 2 & 3 Feature Extraction + XGBoost ML Prediction
        features = extract_features(url)
        import pdg_ml
        ml_res = pdg_ml.predict_risk(features)
        
        ml_score = ml_res.get("ml_score", 50.0)
        shap_explain = ml_res.get("shap_explain", [])
        
        reasons.extend(shap_explain)
        
        # Final Ensemble Score
        final_score = round(0.3 * quick_score + 0.7 * ml_score, 2)
        final_score = min(max(final_score, 0.0), 100.0)

        # Risk Level
        if final_score >= 70.0:
            level = "อันตราย"
        elif final_score >= 40.0:
            level = "เสี่ยง"
        else:
            level = "ปลอดภัย"

        elapsed_ms = int((time.time() - start_time) * 1000)

        return {
            "final_score": final_score,
            "level": level,
            "reasons": reasons,
            "response_time_ms": elapsed_ms
        }
    except Exception as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "final_score": 50.0,
            "level": "เสี่ยง",
            "reasons": [f"Processing error fallback: {str(e)}"],
            "response_time_ms": elapsed_ms
        }


# ==========================================
# Legacy Wrapper for Backward Compatibility
# ==========================================
def analyze_domain(domain: str, url: str = None) -> dict:
    """Wrapper function to maintain backward compatibility with legacy endpoints"""
    target_url = url if url else domain
    result = check_url_full(target_url)
    return {
        "domain": domain,
        "score": result["final_score"],
        "risk": result["level"],
        "details": result["reasons"],
        "whois": {}
    }
