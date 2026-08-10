from __future__ import annotations

import ipaddress
import math
import re
import time
import unicodedata
from collections import Counter, OrderedDict
from copy import deepcopy
from functools import lru_cache
from threading import RLock
from typing import Any
from urllib.parse import parse_qsl, urlparse

from app.rl_engine import predict_rl_score
from app.whois_utils import whois_features


SUSPICIOUS_TLDS = frozenset(
    {
        ".xyz",
        ".cc",
        ".live",
        ".vip",
        ".top",
        ".tk",
        ".ga",
        ".ml",
        ".cf",
        ".gq",
        ".online",
        ".site",
        ".app",
    }
)

KNOWN_BAD_URLS = frozenset(
    {
        "thaigrowthdigitalmarketing.cc",
        "settradethailand.com",
        "athur.net",
        "ezbuy66.com",
        "trade-thai.com",
        "hsgi.xyz",
        "btscswl.com",
        "happinessco.cc",
        "erwz.live",
        "tokts.life",
        "thaibet248.com",
        "thaipvz.com",
        "shopping-now-maket.com",
        "pi-moneyloan.com",
        "bjgth.cc",
        "cryptoxj.com",
        "bonanza-store.net",
        "hshh-banktt.app",
        "dedifeqa-spt.top",
        "royaltrad.vip",
        "jgol.live",
        "affilliiate.com",
        "astalavista.box.sk",
        "crack.ms",
        "cracksearchengine.net",
        "cracks.am",
        "crackfound.com",
        "serialsite.com",
        "crackz.ws",
        "serialcrackz.com",
        "crackteam.ws",
        "zor.org",
        "mscracks.com",
        "anycracks.com",
        "crackspider.net",
        "siamcrack.com",
        "serialz.to",
        "serials.ws",
        "seriall.com",
        "keygen.us",
        "theserials.com",
        "crack-cd.com",
        "crack.cd",
        "grep.ws",
        "asta-killer.com",
        "powerddl.com",
        "d-cracks-serials.com",
        "crackspider.us",
        "download-crack-serial.com",
        "satanwarez.com",
        "atom-soft.com",
        "oday-warez.com",
        "hackzone.us",
        "netvouz.com",
        "keygencrack.com",
        "crackserver.com",
        "cracks.thebugs.ws",
        "download5000.com",
        "freeserials.com",
        "hackpr.net",
        "clean-cracks.com",
        "bestcracks.net",
        "superserials.com",
        "keygen.ru",
        "customize.ru",
        "sh3bwah.com",
        "crackportal.com",
        "crackserial.net",
        "phazeddl.com",
        "serialdevil.com",
    }
)

SUSPICIOUS_WORDS = frozenset(
    {
        "account",
        "banking",
        "bonus",
        "card",
        "cheat",
        "claim",
        "crack",
        "discount",
        "download",
        "free",
        "gift",
        "hack",
        "ibanking",
        "keygen",
        "loan",
        "login",
        "money",
        "promo",
        "secure",
        "signin",
        "trade",
        "update",
        "verify",
    }
)

PHISHING_PATH_INDICATORS = frozenset(
    {"/account", "/banking", "/ibanking", "/login", "/secure", "/signin", "/update", "/verify"}
)

MALICIOUS_EXTENSIONS = frozenset({".apk", ".bat", ".cmd", ".exe", ".msi", ".scr", ".zip"})

SHORTENER_DOMAINS = frozenset(
    {
        "bit.ly",
        "cutt.ly",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "rebrand.ly",
        "shorturl.at",
        "t.co",
        "tiny.cc",
        "tinyurl.com",
    }
)

OFFICIAL_BRAND_DOMAINS = {
    "google": ("google.com", "google.co.th"),
    "paypal": ("paypal.com",),
    "kbank": ("kbank.co.th", "kasikornbank.com"),
    "kasikorn": ("kbank.co.th", "kasikornbank.com"),
    "scb": ("scb.co.th", "scbx.com"),
    "bangkokbank": ("bangkokbank.com",),
    "bbl": ("bangkokbank.com",),
    "krungthai": ("krungthai.com", "ktb.co.th"),
    "ttb": ("ttbbank.com",),
    "tmb": ("ttbbank.com",),
    "gsb": ("gsb.or.th",),
    "baac": ("baac.or.th",),
    "truemoney": ("truemoney.com", "truemoney.co.th"),
    "shopee": ("shopee.co.th", "shopee.com"),
    "lazada": ("lazada.co.th", "lazada.com"),
    "facebook": ("facebook.com",),
    "instagram": ("instagram.com",),
    "line": ("line.me", "linecorp.com"),
    "mflow": ("mflowthai.com",),
    "dlt": ("dlt.go.th",),
    "pea": ("pea.co.th",),
    "mea": ("mea.or.th",),
    "sso": ("sso.go.th",),
}

TRUSTED_DOMAINS = frozenset(
    {
        "amazon.com",
        "apple.com",
        "bangkokbank.com",
        "bbc.com",
        "cloudflare.com",
        "cnn.com",
        "facebook.com",
        "fastapi.tiangolo.com",
        "github.com",
        "google.com",
        "kasikornbank.com",
        "krungthai.com",
        "lazada.co.th",
        "linkedin.com",
        "medium.com",
        "microsoft.com",
        "netflix.com",
        "python.org",
        "reddit.com",
        "scb.co.th",
        "shopee.co.th",
        "stackover-flow.com",
        "twitter.com",
        "wikipedia.org",
        "youtube.com",
    }
)

BRAND_TYPO_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"g[0o]{2}gle",
        r"paypa[l1i]",
        r"kbank",
        r"kasikorn",
        r"scb[-_]?online",
        r"scbb",
        r"krungthai",
        r"bangkokbank",
        r"bbl",
        r"ttb[-_]?bank",
        r"tmb",
        r"truemoney",
        r"shopee{2,}",
        r"lazada{2,}",
        r"facebook",
        r"instagram",
        r"line[-_]?official",
    )
)

COMMON_SECOND_LEVEL_SUFFIXES = frozenset(
    {
        "ac.th",
        "co.th",
        "go.th",
        "in.th",
        "or.th",
        "net.th",
    }
)

ANALYSIS_CACHE_TTL = 3600
ANALYSIS_CACHE_MAX_SIZE = 512
FULL_CHECK_CACHE_TTL = 300
FULL_CHECK_CACHE_MAX_SIZE = 1024
WHOIS_CACHE_TTL = 24 * 3600
WHOIS_CACHE_MAX_SIZE = 1024

_analysis_cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_full_check_cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_whois_cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_cache_lock = RLock()

# Backwards-compatible alias for code that may inspect the old module global.
ANALYSIS_CACHE = _analysis_cache
CACHE_TTL = ANALYSIS_CACHE_TTL


def calculate_entropy(text: str) -> float:
    """คำนวณ Shannon Entropy เพื่อตรวจจับชื่อโดเมนที่สุ่มสร้างอัตโนมัติ (DGA)"""
    if not text:
        return 0.0

    total = len(text)
    counts = Counter(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _cache_get(cache: OrderedDict[str, tuple[float, dict[str, Any]]], key: str) -> dict[str, Any] | None:
    now = time.monotonic()
    with _cache_lock:
        item = cache.get(key)
        if item is None:
            return None

        expiry, value = item
        if now >= expiry:
            cache.pop(key, None)
            return None

        cache.move_to_end(key)
        return deepcopy(value)


def _cache_set(
    cache: OrderedDict[str, tuple[float, dict[str, Any]]],
    key: str,
    value: dict[str, Any],
    ttl: int,
    max_size: int,
) -> None:
    with _cache_lock:
        cache[key] = (time.monotonic() + ttl, deepcopy(value))
        cache.move_to_end(key)

        while len(cache) > max_size:
            cache.popitem(last=False)


def _coerce_url(value: str | None) -> str:
    return (value or "").strip().replace(" ", "")


def _ensure_parseable_url(value: str) -> str:
    if "://" in value:
        return value
    return f"http://{value}"


def _parsed_url(value: str):
    return urlparse(_ensure_parseable_url(_coerce_url(value)))


def _normalize_host(host: str | None) -> str:
    return (host or "").strip().strip(".").lower()


def _host_from_value(value: str | None) -> str:
    raw = _coerce_url(value)
    if not raw:
        return ""

    parsed = _parsed_url(raw)
    host = parsed.hostname
    if host:
        return _normalize_host(host)

    return _normalize_host(raw.split("/", 1)[0].split(":", 1)[0])


def _url_context(url: str | None, domain: str | None = None) -> tuple[str, str, Any]:
    raw_url = _coerce_url(url or domain)
    parsed = _parsed_url(raw_url)
    host = _normalize_host(parsed.hostname) or _host_from_value(domain)
    normalized_url = raw_url.lower()
    return normalized_url, host, parsed


@lru_cache(maxsize=4096)
def _ip_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _is_ip_address(host: str) -> bool:
    return _ip_address(host) is not None


def _is_loopback_or_localhost(host: str) -> bool:
    if host == "localhost":
        return True

    ip = _ip_address(host)
    return bool(ip and ip.is_loopback)


def _is_private_or_reserved_ip(host: str) -> bool:
    ip = _ip_address(host)
    if not ip:
        return False

    return ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast


def _tld(host: str) -> str:
    if not host or _is_ip_address(host):
        return ""

    labels = host.rsplit(".", 1)
    return f".{labels[-1]}" if len(labels) == 2 else ""


def _registered_domain(host: str) -> str:
    if not host or _is_ip_address(host):
        return host

    labels = host.split(".")
    if len(labels) <= 2:
        return host

    suffix2 = ".".join(labels[-2:])
    if suffix2 in COMMON_SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


def _is_same_or_subdomain(host: str, root: str) -> bool:
    return host == root or host.endswith(f".{root}")


def _is_trusted_host(host: str) -> bool:
    return any(_is_same_or_subdomain(host, trusted) for trusted in TRUSTED_DOMAINS)


def _brand_from_official_host(host: str) -> str | None:
    for brand, domains in OFFICIAL_BRAND_DOMAINS.items():
        if any(_is_same_or_subdomain(host, official) for official in domains):
            return brand
    return None


def _matched_bad_url(url: str) -> str | None:
    return next((bad_url for bad_url in KNOWN_BAD_URLS if bad_url in url), None)


def _has_suspicious_tld(host: str) -> bool:
    return _tld(host) in SUSPICIOUS_TLDS


def _main_label(host: str) -> str:
    registered = _registered_domain(host)
    if not registered or _is_ip_address(registered):
        return registered

    suffix2 = ".".join(registered.split(".")[-2:])
    if suffix2 in COMMON_SECOND_LEVEL_SUFFIXES:
        return registered.split(".", 1)[0]

    return registered.split(".", 1)[0]


def _path_has_indicator(path: str, indicator: str) -> bool:
    return path == indicator or path.startswith(f"{indicator}/") or indicator in path


def _dedupe_reasons(reasons: list[str]) -> list[str]:
    seen = set()
    result = []
    for reason in reasons:
        safe_reason = _plain_text(reason)
        if safe_reason not in seen:
            seen.add(safe_reason)
            result.append(safe_reason)
    return result


def _plain_text(value: Any) -> str:
    text = str(value)
    return "".join(
        char
        for char in text
        if unicodedata.category(char) != "So" and char not in {"\ufe0f", "\u200d"}
    ).strip()


def _brand_impersonation_reason(url: str, host: str) -> str | None:
    if not host or _brand_from_official_host(host):
        return None

    # 1. Subdomain impersonation check (e.g. scb.co.th.fake-site.com)
    for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
        for official in official_domains:
            if official in host and not _is_same_or_subdomain(host, official):
                return f"ตรวจพบการนำโดเมนทางการ ({official}) มาใส่เป็น Subdomain เพื่อหลอกลวง"

    # 2. Brand keyword inside unverified URL / Domain
    for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
        if brand in url:
            official = ", ".join(official_domains)
            return f"พบชื่อแบรนด์ '{brand}' แต่โดเมนไม่ตรงกับเว็บทางการ ({official})"

    # 3. Regex Typo patterns
    for pattern in BRAND_TYPO_PATTERNS:
        if pattern.search(url):
            return f"ตรวจพบรูปแบบสะกดเลียนแบบแบรนด์: {pattern.pattern}"

    # 4. Fuzzy Typosquatting distance check
    main_lbl = _main_label(host)
    if main_lbl and len(main_lbl) >= 4:
        for brand in ["kbank", "kasikorn", "scb", "krungthai", "bangkokbank", "shopee", "lazada", "truemoney", "mflow"]:
            dist = _edit_distance(main_lbl.lower(), brand)
            if 1 <= dist <= 2 and len(main_lbl) >= len(brand) - 1:
                return f"ชื่อโดเมน '{main_lbl}' มีการสะกดคล้ายแบรนด์ '{brand}' ผิดปกติ (Typosquatting Risk)"

    return None


def _risk_level(score: float) -> str:
    if score >= 70:
        return "อันตราย"
    if score >= 40:
        return "เสี่ยง"
    return "ปลอดภัย"


def _legacy_risk_level(score: float) -> str:
    if score >= 70:
        return "อันตรายมาก"
    if score >= 40:
        return "เสี่ยง"
    return "ปลอดภัย"


def _safe_whois_features(host: str) -> dict[str, Any]:
    normalized_host = _normalize_host(host)
    if not normalized_host or _is_ip_address(normalized_host) or _is_loopback_or_localhost(normalized_host):
        return {"domain_age_days": None, "registrar": "Unavailable"}

    cached = _cache_get(_whois_cache, normalized_host)
    if cached is not None:
        return cached

    result: dict[str, Any]
    try:
        raw_result = whois_features(normalized_host)
        if isinstance(raw_result, dict):
            result = dict(raw_result)
        else:
            result = {"domain_age_days": None, "registrar": "Unknown"}
    except Exception:
        result = {"domain_age_days": None, "registrar": "Unknown"}

    result["domain_age_days"] = _coerce_domain_age(result.get("domain_age_days"))
    result["registrar"] = _plain_text(result.get("registrar") or "Unknown")
    _cache_set(_whois_cache, normalized_host, result, WHOIS_CACHE_TTL, WHOIS_CACHE_MAX_SIZE)
    return result


def _coerce_domain_age(value: Any) -> int | None:
    try:
        age = int(value)
    except (TypeError, ValueError):
        return None

    return age if age > 0 else None


def _domain_age_feature(host: str) -> int:
    if not host or _is_ip_address(host):
        return 0
    if _is_trusted_host(host):
        return 3650
    if _has_suspicious_tld(host):
        return 30
    return 365


def _edit_distance(left: str, right: str) -> int:
    try:
        import Levenshtein  # type: ignore

        return int(Levenshtein.distance(left, right))
    except Exception:
        previous = list(range(len(right) + 1))
        for i, left_char in enumerate(left, 1):
            current = [i]
            for j, right_char in enumerate(right, 1):
                insert_cost = current[j - 1] + 1
                delete_cost = previous[j] + 1
                replace_cost = previous[j - 1] + (left_char != right_char)
                current.append(min(insert_cost, delete_cost, replace_cost))
            previous = current
        return previous[-1]


def _brand_distance(host: str, brand: str) -> float:
    if not host:
        return float(len(brand))

    labels = [label for label in re.split(r"[^a-z0-9]+", host.lower()) if label]
    if not labels:
        return float(len(brand))

    distances = []
    for label in labels:
        if brand in label:
            distances.append(0)
        else:
            distances.append(_edit_distance(label, brand))

    return float(min(min(distances), 20))


def quick_check(url: str) -> dict[str, Any]:
    """
    Layer 1: ตรวจ URL อย่างรวดเร็วด้วย blacklist และ heuristic ที่ไม่พึ่ง network
    เพื่อให้ใช้ได้เร็วทั้งในเว็บ, extension และ unit tests.
    """
    raw_url = _coerce_url(url)
    has_explicit_scheme = "://" in raw_url
    normalized_url, host, parsed = _url_context(raw_url)
    path = (parsed.path or "").lower()
    registered_domain = _registered_domain(host)

    score = 0
    reasons: list[str] = []

    if not normalized_url:
        return {"score": 0, "reasons": ["ไม่ได้ระบุ URL"]}

    if _is_loopback_or_localhost(host):
        return {"score": 0, "reasons": ["เป็น Localhost สำหรับทดสอบภายในเครื่อง"]}

    bad_url = _matched_bad_url(normalized_url)
    if bad_url:
        return {
            "score": 100,
            "reasons": [f"ตรวจพบในฐานข้อมูลเว็บอันตราย (Blacklist ความเสี่ยง 100%): {bad_url}"],
        }

    if _is_ip_address(host):
        score += 35
        reasons.append(f"ใช้ IP Address โดยตรงเป็นโฮสต์ ({host}) (+35%)")
        if _is_private_or_reserved_ip(host):
            score += 15
            reasons.append("IP อยู่ในช่วง private/reserved จึงไม่ควรสแกนหรือเชื่อถือจากภายนอก (+15%)")

    if parsed.username or parsed.password or "@" in normalized_url.split("/", 3)[-1]:
        score += 30
        reasons.append("พบสัญลักษณ์ @ ใน URL ซึ่งมักใช้ซ่อนโดเมนปลายทางจริง (+30%)")

    if _has_suspicious_tld(host):
        score += 15
        reasons.append(f"ใช้นามสกุลโดเมนที่มีความเสี่ยงสูง: {_tld(host)} (+15%)")

    found_words = [word for word in SUSPICIOUS_WORDS if word in normalized_url]
    if found_words:
        w_score = min(30, len(found_words) * 10)
        score += w_score
        reasons.append(f"พบคำที่มักใช้ในเว็บหลอกลวง: {', '.join(sorted(found_words)[:5])} (+{w_score}%)")

    path_hits = [indicator for indicator in PHISHING_PATH_INDICATORS if _path_has_indicator(path, indicator)]
    if path_hits:
        p_score = min(30, len(path_hits) * 12)
        score += p_score
        reasons.append(f"พบ path ที่น่าสงสัย: {', '.join(sorted(path_hits)[:4])} (+{p_score}%)")

    if any(path.endswith(ext) for ext in MALICIOUS_EXTENSIONS):
        score += 20
        reasons.append("ลิงก์ชี้ไปยังไฟล์ที่อาจเป็นอันตราย (+20%)")

    if "xn--" in host:
        score += 25
        reasons.append("พบโดเมน Punycode ซึ่งอาจใช้ปลอมแปลงตัวอักษร (+25%)")

    main_label = _main_label(host)
    entropy = calculate_entropy(main_label)
    if len(main_label) >= 6 and entropy > 3.8:
        score += 20
        reasons.append(f"ชื่อโดเมนมีความสุ่มสูงผิดปกติ (Entropy: {entropy:.2f}) (+20%)")

    digit_count = sum(char.isdigit() for char in host)
    if digit_count > 3:
        score += 10
        reasons.append("ชื่อโดเมนมีตัวเลขปนอยู่มากผิดปกติ (+10%)")

    if "-" in registered_domain and not _is_trusted_host(host):
        score += 5
        reasons.append("มีเครื่องหมาย - ในชื่อโดเมน (+5%)")

    host_labels = host.split(".") if host else []
    if len(host_labels) >= 4 and not _is_trusted_host(host):
        score += 10
        reasons.append("มีชั้น subdomain หลายระดับผิดปกติ (+10%)")

    if registered_domain in SHORTENER_DOMAINS:
        score += 25
        reasons.append("ใช้บริการย่อลิงก์ ทำให้ตรวจปลายทางจริงได้ยาก (+25%)")

    brand_reason = _brand_impersonation_reason(normalized_url, host)
    if brand_reason:
        score += 25
        reasons.append(f"{brand_reason} (+25%)")

    if has_explicit_scheme and parsed.scheme == "http":
        score += 5
        reasons.append("ไม่มีการเข้ารหัสการเชื่อมต่อ (HTTP) (+5%)")

    if _is_trusted_host(host) and score <= 15:
        score = max(0, score - 10)
        if not reasons:
            reasons.append("โดเมนอยู่ในรายการเว็บไซต์ที่เชื่อถือได้")

    return {"score": min(int(score), 100), "reasons": _dedupe_reasons(reasons)}


def extract_features(url: str) -> dict[str, int | float]:
    """
    Layer 2: แปลง URL เป็น 20 features ตามสัญญาของ pdg_ml.FEATURE_NAMES.
    ฟังก์ชันนี้ตั้งใจให้เร็วและ deterministic จึงไม่เรียก WHOIS/network.
    """
    normalized_url, host, parsed = _url_context(url)
    path = parsed.path or ""
    query = parsed.query or ""
    main_label = _main_label(host)
    labels = host.split(".") if host else []
    registered_domain = _registered_domain(host)

    suffix_labels = registered_domain.split(".") if registered_domain else []
    subdomain_labels = labels[: max(0, len(labels) - len(suffix_labels))]
    subdomain = ".".join(subdomain_labels)

    return {
        "url_length": float(len(normalized_url)),
        "domain_length": float(len(host)),
        "num_dots": float(host.count(".")),
        "num_hyphens": float(host.count("-")),
        "num_digits": float(sum(char.isdigit() for char in host)),
        "has_https": 1.0 if parsed.scheme == "https" else 0.0,
        "has_at": 1.0 if parsed.username or parsed.password or "@" in normalized_url else 0.0,
        "has_ip": 1.0 if _is_ip_address(host) else 0.0,
        "entropy": round(calculate_entropy(main_label), 4),
        "domain_age_days": float(_domain_age_feature(host)),
        "tld_abnormal": 1.0 if _has_suspicious_tld(host) else 0.0,
        "brand_distance_kbank": _brand_distance(host, "kbank"),
        "brand_distance_scb": _brand_distance(host, "scb"),
        "brand_distance_shopee": _brand_distance(host, "shopee"),
        "subdomain_length": float(len(subdomain)),
        "path_length": float(len(path)),
        "has_punycode": 1.0 if "xn--" in host else 0.0,
        "num_params": float(len(parse_qsl(query, keep_blank_values=True))),
        "is_shortened_url": 1.0 if registered_domain in SHORTENER_DOMAINS else 0.0,
        "favicon_match_brand": 1.0 if _brand_from_official_host(host) else 0.0,
    }


def _ml_prediction(features: dict[str, int | float]) -> dict[str, Any]:
    try:
        import pdg_ml

        result = pdg_ml.predict_risk(features)
        if not isinstance(result, dict):
            raise TypeError("pdg_ml.predict_risk returned a non-dict result")
        return {
            "ml_score": float(result.get("ml_score", 50.0)),
            "shap_explain": list(result.get("shap_explain", [])),
        }
    except Exception as exc:
        return {"ml_score": 50.0, "shap_explain": [f"ML fallback: {exc}"]}


def check_url_full(url: str) -> dict[str, Any]:
    """
    Layer 3: รวม quick heuristics + feature extraction + ML score.
    คืน schema ที่ใช้กับ test และตัวอย่างการใช้งาน.
    """
    cache_key = _coerce_url(url).lower()
    cached = _cache_get(_full_check_cache, cache_key)
    if cached is not None:
        return cached

    start = time.perf_counter()
    normalized_url, host, _ = _url_context(url)
    quick = quick_check(normalized_url)
    features = extract_features(normalized_url)

    quick_score = float(quick["score"])
    use_ml = not ((quick_score >= 40.0) or (_is_trusted_host(host) and quick_score <= 15.0))

    if use_ml:
        ml_result = _ml_prediction(features)
        ml_score = max(0.0, min(float(ml_result["ml_score"]), 100.0))
    else:
        ml_result = {"ml_score": quick_score, "shap_explain": []}
        ml_score = quick_score

    if not use_ml:
        final_score = quick_score
    elif quick_score >= 80:
        final_score = max(quick_score, quick_score * 0.75 + ml_score * 0.25)
    elif quick_score >= 40:
        final_score = quick_score * 0.70 + ml_score * 0.30
    else:
        final_score = quick_score * 0.55 + ml_score * 0.45

    if _is_trusted_host(host) and quick_score <= 15:
        final_score = min(final_score, 20.0)

    final_score = round(max(0.0, min(final_score, 100.0)), 2)
    level = _risk_level(final_score)

    reasons = list(quick["reasons"])
    if level != "ปลอดภัย" and ml_result["shap_explain"]:
        reasons.extend(f"ML: {item}" for item in ml_result["shap_explain"][:3])

    result = {
        "url": normalized_url,
        "domain": host,
        "final_score": final_score,
        "level": level,
        "reasons": _dedupe_reasons(reasons),
        "response_time_ms": round((time.perf_counter() - start) * 1000, 2),
        "quick_score": round(quick_score, 2),
        "ml_score": round(ml_score, 2),
        "features": features,
    }

    _cache_set(_full_check_cache, cache_key, result, FULL_CHECK_CACHE_TTL, FULL_CHECK_CACHE_MAX_SIZE)
    return deepcopy(result)


def analyze_domain(domain: str, url: str | None = None) -> dict[str, Any]:
    """
    Backwards-compatible analyzer used by the existing FastAPI routes.
    """
    normalized_url, host, _ = _url_context(url, domain)
    cache_key = (normalized_url or host).lower()
    cached = _cache_get(_analysis_cache, cache_key)
    if cached is not None:
        return cached

    if _is_loopback_or_localhost(host):
        result = {
            "domain": domain,
            "score": 0,
            "risk": "ปลอดภัย",
            "details": ["เป็น Localhost สำหรับทดสอบภายในเครื่อง"],
            "whois": {},
        }
        _cache_set(_analysis_cache, cache_key, result, ANALYSIS_CACHE_TTL, ANALYSIS_CACHE_MAX_SIZE)
        return deepcopy(result)

    quick = quick_check(normalized_url or domain)
    details = list(quick["reasons"])
    score = float(quick["score"])
    whois_data: dict[str, Any] = {}

    if score < 100:
        try:
            rl_score, rl_conf = predict_rl_score(normalized_url or host)
            rl_score = max(0.0, min(float(rl_score), 100.0))
            details.append(f"AI (RL) Score: {rl_score:.1f}/100 (Confidence: {rl_conf})")
        except Exception as exc:
            rl_score = 50.0
            details.append(f"AI (RL) ใช้ค่า fallback เนื่องจากประมวลผลไม่สำเร็จ: {exc}")

        if score >= 70:
            score = max(score, score * 0.70 + rl_score * 0.30)
        else:
            score = score * 0.40 + rl_score * 0.60

        whois_data = _safe_whois_features(host)
        age_days = _coerce_domain_age(whois_data.get("domain_age_days"))
        if age_days is not None and age_days < 180:
            score += 15
            details.append("โดเมนอายุสั้น")

    score = round(max(0.0, min(score, 100.0)), 2)
    result = {
        "domain": domain,
        "score": score,
        "risk": _legacy_risk_level(score),
        "details": _dedupe_reasons(details),
        "whois": whois_data,
    }

    _cache_set(_analysis_cache, cache_key, result, ANALYSIS_CACHE_TTL, ANALYSIS_CACHE_MAX_SIZE)
    return deepcopy(result)
