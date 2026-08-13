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


def analyze_image_vision(image_bytes: bytes, mime_type: str = "image/png") -> dict[str, Any]:
    """Analyze image OCR and estimate likelihood of generative-AI involvement."""
    default_res = {
        "text": "", "is_ai": False, "ai_score": 0,
        "ai_reason": "ยังไม่สามารถวิเคราะห์ภาพเพื่อประเมิน AI ได้",
        "ai_confidence": "Unknown", "ai_signals": [], "ai_status": "unavailable"
    }
    if not client:
        return default_res

    models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
    prompt = r"""
คุณเป็นผู้เชี่ยวชาญด้านการวิเคราะห์ภาพและการตรวจจับภาพที่สร้างหรือแก้ไขด้วย AI
วิเคราะห์ภาพนี้ 2 งาน: (1) อ่านข้อความไทย/อังกฤษที่เห็น (2) ประเมินว่าภาพมีแนวโน้มถูกสร้างหรือแก้ไขด้วย Generative AI หรือไม่
ห้ามอ้างว่าตรวจได้ 100% และห้ามตัดสินจากความสวย/ความคมเพียงอย่างเดียว
พิจารณา artifact ของมือ นิ้ว ฟัน ตา ใบหู ตัวอักษร โลโก้ พื้นผิว แสง เงา การสะท้อน perspective ขอบวัตถุ รายละเอียดเล็ก ๆ และ metadata ที่มองเห็นได้
ถ้าหลักฐานไม่พอให้ใช้ confidence ต่ำหรือ Unknown
ai_score คือคะแนนความเป็นไปได้ว่าเกี่ยวข้องกับ AI ไม่ใช่เปอร์เซ็นต์ความถูกต้องของตัวตรวจจับ
เกณฑ์: 0-29 ต่ำมาก, 30-59 ไม่แน่ชัด, 60-79 มีแนวโน้ม, 80-100 มีหลักฐานสูง
ตอบ JSON เท่านั้น:
{"text":"","is_ai":true,"ai_score":0,"ai_confidence":"High","ai_reason":"คำอธิบายภาษาไทยสั้น ๆ","ai_signals":["หลักฐานที่สังเกตได้"]}
กฎ: is_ai=true เมื่อ score>=60; High เมื่อ score>=80 และมีหลักฐานอย่างน้อย 2 ข้อ; Medium 60-79; Low 30-59; Unknown เมื่อหลักฐานไม่เพียงพอ
"""
    for mod_name in models_to_try:
        try:
            from google.genai import types
            part=types.Part.from_bytes(data=image_bytes,mime_type=mime_type or "image/png")
            res=client.models.generate_content(model=mod_name,contents=[part,prompt])
            if not res or not getattr(res,"text",None): continue
            cleaned=res.text.strip()
            if "```" in cleaned:
                m=re.search(r"```(?:json)?\s*(.*?)\s*```",cleaned,re.S|re.I)
                if m: cleaned=m.group(1).strip()
            data=json.loads(cleaned)
            try: score=max(0,min(100,int(float(data.get("ai_score",0)))))
            except (TypeError,ValueError): score=0
            signals=data.get("ai_signals",[])
            if isinstance(signals,str): signals=[signals]
            if not isinstance(signals,list): signals=[]
            signals=[str(x).strip() for x in signals if str(x).strip()][:8]
            conf=str(data.get("ai_confidence","")).title()
            if conf not in {"High","Medium","Low","Unknown"}:
                conf="High" if score>=80 and len(signals)>=2 else "Medium" if score>=60 else "Low" if score>=30 else "Unknown"
            is_ai=score>=60
            reason=str(data.get("ai_reason","")).strip() or ("พบสัญญาณของภาพที่เกี่ยวข้องกับการสร้างหรือแก้ไขด้วย AI" if is_ai else "ยังไม่พบหลักฐานเด่นชัดที่บ่งชี้ว่าภาพสร้างด้วย AI")
            return {"text":str(data.get("text","")).strip(),"is_ai":is_ai,"ai_score":score,"ai_reason":reason[:500],"ai_confidence":conf,"ai_signals":signals,"ai_status":"analyzed"}
        except Exception as exc:
            print(f"Gemini Vision model {mod_name} error: {exc}")
    return {**default_res,"ai_reason":"ระบบไม่สามารถวิเคราะห์สัญญาณ AI ของภาพได้ในขณะนี้","ai_status":"failed"}

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
