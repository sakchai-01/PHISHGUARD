import os
import re
import json
from dotenv import load_dotenv
from typing import List, Optional, Dict, Any

try:
    import google.genai as genai
except ImportError:
    genai = None

# ==========================================
# 1. URL Risk Engine (from pdg_ml.py)
# ==========================================

KNOWN_BAD_URLS = [
    'download5000.com', 'thaigrowthdigitalmarketing.cc', 'settradethailand.com',
    'ezbuy66.com', 'trade-thai.com', 'hsgi.xyz', 'btscswl.com', 'happinessco.cc',
    'erwz.live', 'tokts.life', 'thaibet248.com', 'thaipvz.com', 'shopping-now-maket.com',
    'pi-moneyloan.com', 'bjgth.cc', 'cryptoxj.com', 'bonanza-store.net', 'hshh-banktt.app',
    'royaltrad.vip', 'astalavista.box.sk', 'crack.ms', 'seriall.com', 'serialz.to'
]

from app.domain_checker import check_url_full, quick_check

def predict_risk(url: str):
    """
    วิเคราะห์ความเสี่ยงของ URL ด้วย 3-Layer Phishing Guard (20-Feature Engine)
    Returns: (score: int, risk_level: str, status: str, reasons: list[str])
    """
    result = check_url_full(url)
    score = int(result.get("final_score", 0))
    risk_level = result.get("level", "ปลอดภัย")
    
    if score >= 70:
        status = "Dangerous"
    elif score >= 40:
        status = "Warning"
    else:
        status = "Safe"
        
    reasons = result.get("reasons", [])
    return score, risk_level, status, reasons


# ==========================================
# 2. Gemini AI Setup
# ==========================================

load_dotenv()
GEMINI_KEY = os.getenv("GEMINI_API_KEY")

if genai and GEMINI_KEY:
    try:
        client = genai.Client(api_key=GEMINI_KEY)
        print("DEBUG: Gemini (google.genai) initialized successfully")
    except Exception as e:
        print(f"Gemini init error: {e}")
        client = None
else:
    client = None

model = client if client else None

# System prompt for JANIS_AI
SYSTEM_PROMPT = """You are 'JANIS_AI', a high-level AI Cybersecurity Specialist.
You are female, professional, and helpful. Always use polite female Thai particles like 'ค่ะ' or 'นะคะ'. 
Avoid using male pronouns like 'ผม' and use 'ดิฉัน' or simply omit pronouns where appropriate.
Your mission is to analyze messages, links, or files for phishing, scams, and cyber threats.

GUIDELINES:
1. If the user asks for a security analysis, you MUST provide a structured JSON response within your message.
2. If the user is just chatting or asking general questions, respond naturally but maintain your professional 'Security Expert' persona.
3. Pay special attention to brand impersonation and suspicious domain structures (e.g., official brand keywords embedded in untrusted domains or subdomains, such as 'scb-online.top' or 'kbank.co.th.scam.net').
4. Your analysis should be thorough but the advice should be easy to follow.

DATA FORMAT FOR ANALYSIS:
When you detect a threat or are asked to analyze something, include this JSON structure in your response:
{
  "analysis_result": {
    "is_scam": boolean,
    "risk_score": integer (0-100),
    "category": "Phishing" | "Scam" | "Malware" | "Safe" | "General",
    "detected_flags": ["Reason 1", "Reason 2"],
    "recommendation": "Detailed advice here"
  }
}

IMPORTANT: Even if you provide a natural explanation, the JSON block must be present if there's any risk assessment involved. Keep the JSON clean and valid.
"""


# ==========================================
# 3. Core AI Response Function
# ==========================================

def get_ai_response(message: str, history: Optional[List[Dict[str, Any]]] = None) -> str:
    """
    Generates a response using Gemini AI.
    Automatically pre-analyzes any URL in the message using the local
    Heuristic engine and injects the result into the AI prompt.
    """
    message_clean = message.strip().lower()

    # Shortcut: admin login redirect
    if message_clean in ["admin", "แอดมิน"]:
        return (
            "พบความต้องการเข้าสู่ระบบบริหารจัดการ (Neural Command Center) ค่ะ "
            "ท่านสามารถเข้าสู่ระบบเพื่อปฏิบัติหน้าที่ได้ที่ลิงก์นี้เลยนะคะ: "
            "<a href='/admin/login' class='text-cyan-400 font-bold underline transition hover:text-cyan-300'>"
            "[Neural Command Access]</a>"
        )

    if not model:
        return json.dumps({
            "error": "Gemini AI provider not configured.",
            "details": "Checking if GEMINI_API_KEY is in .env and google-genai is installed."
        })

    # --- Pre-analyze URLs found in the message with local Heuristics ---
    url_pattern = re.compile(
        r'(https?://[^\s]+|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)',
        re.IGNORECASE
    )
    found_urls = url_pattern.findall(message)
    heuristic_context = ""
    if found_urls:
        heuristic_lines = []
        for u in found_urls:
            score, risk_level, status, reasons = predict_risk(u)
            reason_str = ", ".join(reasons) if reasons else "ไม่พบรูปแบบที่น่าสงสัย"
            heuristic_lines.append(
                f"  - URL: {u} | Score: {score}/100 | Level: {risk_level} | "
                f"Status: {status} | Reasons: {reason_str}"
            )
        heuristic_context = (
            "\n\n[LOCAL HEURISTIC PRE-ANALYSIS — use this data to inform your response]:\n"
            + "\n".join(heuristic_lines)
        )

    try:
        full_message = SYSTEM_PROMPT + heuristic_context + "\n\nUser message:\n" + message
        response = model.models.generate_content(
            model="gemini-2.5-flash",
            contents=full_message
        )
        # pyrefly: ignore [bad-return]
        return response.text or "{}"

    except Exception as e:
        print(f"Gemini Error: {e}")
        return json.dumps({
            "error": "AI Response failed",
            "details": str(e)
        })


# ==========================================
# 4. Utility Functions
# ==========================================

def extract_json(response_text: str) -> Optional[Dict[Any, Any]]:
    """
    Utility to extract JSON from AI response if it's wrapped in text or markdown.
    """
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if match:
            try:
                json_str = match.group().strip()
                return json.loads(json_str)
            except Exception:
                pass
    return None
