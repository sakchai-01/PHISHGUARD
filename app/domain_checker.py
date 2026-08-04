import socket
import time
import math
import re
from app.whois_utils import whois_features
from app.rl_engine import predict_rl_score

SUSPICIOUS_TLDS = ['.xyz', '.cc', '.live', '.vip', '.top', '.tk', '.ga', '.ml', '.cf', '.gq', '.online', '.site']
KNOWN_BAD_URLS = [
    'thaigrowthdigitalmarketing.cc', 'settradethailand.com', 'athur.net', 'ezbuy66.com',
    'trade-thai.com', 'hsgi.xyz', 'btscswl.com', 'happinessco.cc', 'erwz.live',
    'tokts.life', 'thaibet248.com', 'thaipvz.com', 'shopping-now-maket.com',
    'pi-moneyloan.com', 'bjgth.cc', 'cryptoxj.com', 'bonanza-store.net', 'hshh-banktt.app',
    'dedifeqa-spt.top', 'royaltrad.vip', 'jgol.live', 'affilliiate.com',
    'astalavista.box.sk', 'crack.ms', 'cracksearchengine.net', 'cracks.am',
    'crackfound.com', 'serialsite.com', 'crackz.ws', 'serialcrackz.com',
    'crackteam.ws', 'zor.org', 'mscracks.com', 'anycracks.com', 'crackspider.net',
    'siamcrack.com', 'serialz.to', 'serials.ws', 'seriall.com', 'keygen.us',
    'theserials.com', 'crack-cd.com', 'crack.cd', 'grep.ws', 'asta-killer.com',
    'powerddl.com', 'd-cracks-serials.com', 'crackspider.us', 'download-crack-serial.com',
    'satanwarez.com', 'atom-soft.com', 'oday-warez.com', 'hackzone.us', 'netvouz.com',
    'keygencrack.com', 'crackserver.com', 'cracks.thebugs.ws', 'download5000.com',
    'freeserials.com', 'hackpr.net', 'clean-cracks.com', 'bestcracks.net',
    'superserials.com', 'keygen.ru', 'customize.ru', 'sh3bwah.com', 'crackportal.com',
    'crackserial.net', 'phazeddl.com', 'serialdevil.com'
]

BRAND_TYPOSQUATTING_PATTERNS = [
    r'g[0o]{2}gle', r'paypa[l1i]', r'kbank', r'kasikorn', r'scb[-_]?online',
    r'krungthai', r'bangkokbank', r'ttb[-_]?bank', r'tmb', r'truemoney',
    r'shopee', r'lazada', r'facebook', r'instagram', r'line[-_]?official'
]

# Simple in-memory cache
ANALYSIS_CACHE = {}
CACHE_TTL = 3600  # 1 hour

def calculate_entropy(text: str) -> float:
    """คำนวณ Shannon Entropy เพื่อตรวจจับชื่อโดเมนที่สุ่มสร้างอัตโนมัติ (DGA)"""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def analyze_domain(domain, url=None):
    current_time = time.time()
    cache_key = url if url else domain
    
    if cache_key in ANALYSIS_CACHE:
        cached = ANALYSIS_CACHE[cache_key]
        if current_time < cached["expiry"]:
            return cached["result"]

    # 0. Whitelist Check (Localhost & Internal IPs)
    check_domain = domain.lower().split(':')[0]
    if check_domain in ['127.0.0.1', 'localhost'] or check_domain.startswith('192.168.'):
        result = {
            "domain": domain,
            "score": 0,
            "risk": "ปลอดภัย",
            "details": ["เป็น Localhost หรือ IP ภายในเครื่อง (ปลอดภัย 100%) 🟢"],
            "whois": {}
        }
        ANALYSIS_CACHE[cache_key] = {"result": result, "expiry": current_time + CACHE_TTL}
        return result

    score = 0
    details = []

    # 1. เช็คจาก Built-in Blacklist โดยตรง (Blacklist = 100% ทันที)
    check_url = (url.lower().replace(' ', '') if url else domain.lower())
    for bad_url in KNOWN_BAD_URLS:
        if bad_url in check_url:
            score += 100
            details.append(f'ตรวจพบในฐานข้อมูลเว็บอันตราย (Built-in Blacklist): {bad_url}')
            break

    # ถ้าไม่โดน Blacklist เราจะใช้ RL Model เป็นแกนหลัก (60%) + Heuristics (40%)
    if score < 100:
        # RL Model Prediction (Primary Engine)
        rl_score, rl_conf = predict_rl_score(check_url)
        
        # ถ่วงน้ำหนัก RL 60%
        base_score = rl_score * 0.6
        score += base_score
        details.append(f"🧠 AI (RL) Score: {rl_score:.1f}/100 (Confidence: {rl_conf})")
        
        heuristic_score = 0
        # Whois Check (Backend original feature)
        whois_data = whois_features(domain)
        # pyrefly: ignore [unsupported-operation]
        if whois_data["domain_age_days"] < 180:
            heuristic_score += 15
            details.append("โดเมนอายุสั้น ⚠️")
            
        if "-" in domain:
            heuristic_score += 5
            details.append("มีเครื่องหมาย - ในโดเมน")

        # 2. ตรวจสอบ IP Host Direct Connection (ไม่มีชื่อโดเมน)
        domain_only = domain.split(':')[0]
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_only):
            heuristic_score += 25
            details.append(f'ใช้ IP Address โดยตรงเป็นโฮสต์ ({domain_only}) ⚠️')

        # 3. DGA / Domain Entropy Analysis
        domain_name_part = domain_only.split('.')[0]
        entropy_val = calculate_entropy(domain_name_part)
        if len(domain_name_part) >= 6 and entropy_val > 3.8:
            heuristic_score += 20
            details.append(f'ความสุ่มของชื่อโดเมนสูงผิดปกติ (Entropy: {entropy_val:.2f}) ⚠️')

        # 4. Brand Typosquatting Detection
        for pattern in BRAND_TYPOSQUATTING_PATTERNS:
            if re.search(pattern, check_url):
                heuristic_score += 20
                details.append(f'ตรวจพบพฤติกรรมสะกดเลียนแบบแบรนด์ดัง (Typosquatting): {pattern}')
                break

        # 5. ตรวจสอบคำที่มักพบในเว็บ Phishing/Scam และ Malware/Piracy
        suspicious_words = [
            'download', 'free', 'update', 'login', 'verify', 'account', 
            'banking', 'trade', 'loan', 'money', 'crack', 'hack', 'keygen', 'cheat'
        ]
        for word in suspicious_words:
            if word in check_url:
                heuristic_score += 10
                details.append(f'พบคำเสี่ยงต่อการหลอกลวง: {word}')

        # 6. ตรวจสอบ TLD เสี่ยง
        for tld in SUSPICIOUS_TLDS:
            if check_url.endswith(tld) or f'{tld}/' in check_url:
                heuristic_score += 15
                details.append(f'ใช้นามสกุลโดเมนที่มีความเสี่ยงสูง: {tld}')

        # 7. ตรวจสอบตัวเลขในชื่อโดเมน
        digits = sum(c.isdigit() for c in domain)
        if digits > 3:
            heuristic_score += 10
            details.append('ชื่อโดเมนมีตัวเลขปนอยู่มากผิดปกติ')

        # 5. Path Analysis (Advanced Risk Check)
        if url:
            from urllib.parse import urlparse
            parsed_path = urlparse(url if '://' in url else 'http://' + url).path.lower()
            
            phishing_indicators = ['/login', '/signin', '/verify', '/account', '/banking', '/secure']
            for indicator in phishing_indicators:
                if indicator in parsed_path:
                    heuristic_score += 15
                    details.append(f"พบ Path ที่น่าสงสัย (Phishing Indicator): {indicator}")

            malicious_exts = ['.exe', '.apk', '.bat', '.scr', '.zip']
            for ext in malicious_exts:
                if parsed_path.endswith(ext):
                    heuristic_score += 15
                    details.append(f"พบการเชื่อมโยงไปยังไฟล์ที่อาจเป็นอันตราย: {ext}")
                    
        # 6. Protocol and Prefix checks
        if url:
            check_url_lower = url.lower()
            if check_url_lower.startswith('https://'):
                heuristic_score -= 10
                details.append("มีการเข้ารหัสการเชื่อมต่อ (HTTPS) 🔒")
            elif check_url_lower.startswith('http://'):
                heuristic_score += 5
                details.append("ไม่มีการเข้ารหัสการเชื่อมต่อ (HTTP) ⚠️")
            
            # Check for www. prefix
            if check_url_lower.startswith('www.') or '://www.' in check_url_lower:
                heuristic_score += 10
                details.append("โดเมนใช้ www. (มิจฉาชีพมักใช้เลียนแบบเว็บจริง) ⚠️")
                    
        # ถ่วงน้ำหนัก Heuristics ให้คะแนนรวมกันไม่เกิน 40 (และลดได้ไม่เกิน -20)
        final_heuristics = max(-20, min(heuristic_score, 40))
        score += final_heuristics
        
    else:
        whois_data = {}

    # Cap score at 100
    score = min(score, 100)

    risk = "ปลอดภัย"
    if score >= 70:
        risk = "อันตรายมาก 🔥"
    elif score >= 40:
        risk = "เสี่ยง ⚠️"

    result = {
        "domain": domain,
        "score": score,
        "risk": risk,
        "details": details,
        "whois": whois_data
    }
    
    ANALYSIS_CACHE[cache_key] = {
        "result": result,
        "expiry": current_time + CACHE_TTL
    }
    
    return result
