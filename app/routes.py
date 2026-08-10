import os
import json
import base64
import asyncio
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Request, Form, Response, Depends, status, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from urllib.parse import urlparse

from app.core.database import (
    get_db_connection, save_user_report, add_phishing_url, 
    search_url_in_all, get_admin_by_email, verify_password,
    get_recent_reports, list_admins, add_admin, delete_admin,
    update_report_status, get_report_by_id, add_fake_url, add_safe_url,
    delete_report
)
from app.domain_checker import analyze_domain
from app.brain import get_ai_response, extract_json, analyze_image_vision
import json
import base64

router = APIRouter()
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(_BASE, "templates"))

@router.get("/favicon.ico", status_code=status.HTTP_204_NO_CONTENT)
async def favicon():
    """Suppress favicon 404 error"""
    return ""

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

# ==== STATIC PAGES (NEWS / INFO) ====
@router.get("/news", response_class=HTMLResponse)
async def news(request: Request): return templates.TemplateResponse(request=request, name="news.html")

@router.get("/about", response_class=HTMLResponse)
async def about(request: Request): return templates.TemplateResponse(request=request, name="about.html")

@router.get("/news/{category}", response_class=HTMLResponse)
async def news_category(request: Request, category: str): 
    return templates.TemplateResponse(request=request, name=f"news_{category}.html")

@router.get("/tools/{tool_name}", response_class=HTMLResponse)
async def tools_page(request: Request, tool_name: str):
    return templates.TemplateResponse(request=request, name=f"{tool_name}.html")

@router.get("/contact", response_class=HTMLResponse)
async def contact(request: Request): return templates.TemplateResponse(request=request, name="contact.html")

@router.get("/contact/{sub_page}", response_class=HTMLResponse)
async def contact_sub(request: Request, sub_page: str): 
    return templates.TemplateResponse(request=request, name=f"contact_{sub_page}.html")

@router.get("/report", response_class=HTMLResponse)
async def report_get(request: Request):
    return templates.TemplateResponse(request=request, name="report.html", context={
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
    })

@router.post("/report", response_class=HTMLResponse)
async def report_post(request: Request, email: str = Form(...), url: str = Form(None), description: str = Form(None), type: str = Form(None)):
    print(f"REPORT RECEIVED: Email={email}, Type={type}, URL={url}")
    try:
        report_id = await save_user_report(email=email, report_type=type or "other", url=url or "", description=description or "")
        print(f"Saved report to MongoDB with ID: {report_id}")
    except Exception as e:
        print(f"DB Error: {e}")
        
    return templates.TemplateResponse(request=request, name="report.html", context={
        # pyrefly: ignore [unbound-name]
        "success": f"ขอบคุณสำหรับการแจ้งเบาะแสคุณ {email}! เราจะตรวจสอบโดยเร็วที่สุด (รหัสอ้างอิง: {report_id if 'report_id' in locals() else 'Pending'})",
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
    })

@router.get("/detect/fb", response_class=HTMLResponse)
async def detect_fb(request: Request):
    return templates.TemplateResponse(request=request, name="detect_fb.html", context={
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
    })


# ==== API ENDPOINTS (ASYNC) ====
@router.post("/check")
async def check_url(request: Request):
    data = await request.json()
    url = data.get('url') if data else None

    if not url:
        return JSONResponse({'error': 'No URL provided'}, status_code=400)

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    # 1. Run ML & Heuristics Check (Primary System)
    analysis = await asyncio.to_thread(analyze_domain, domain, url)
    
    # 2. Check Database for overrides (Secondary System)
    db_result = await search_url_in_all(url)
    if db_result:
        col = db_result["collection"]
        doc = db_result["document"]
        if col == "safe_urls":
            analysis["score"] = 0
            analysis["risk"] = "ปลอดภัย (Whitelist)"
            if "เว็บไซต์นี้อยู่ในฐานข้อมูลปลอดภัยของระบบ" not in analysis["details"]:
                analysis["details"].append("เว็บไซต์นี้อยู่ในฐานข้อมูลปลอดภัยของระบบ")
        else:
            analysis["score"] = 100
            analysis["risk"] = "อันตรายมาก 🔥 (Blacklist)"
            bl_msg = f"ระวัง! เว็บไซต์นี้ถูกแจ้งเตือนในฐานข้อมูลระบบ ({doc.get('source', 'admin')})"
            if bl_msg not in analysis["details"]:
                analysis["details"].append(bl_msg)

    return analysis

@router.post("/api/ocr")
async def api_ocr(file: UploadFile = File(...)):
    try:
        content = await file.read()
        mime_type = file.content_type or "image/png"
        text = await asyncio.to_thread(analyze_image_vision, content, mime_type)
        return JSONResponse({
            "success": True,
            "text": text or "",
            "filename": file.filename
        })
    except Exception as e:
        print(f"OCR Endpoint error: {e}")
        return JSONResponse({"success": False, "error": str(e), "text": ""})

@router.post("/scan")
async def scan_url(request: Request):
    data = await request.json()
    url = data.get('url')
    
    if not url:
        return JSONResponse({'error': 'No URL provided'}, status_code=400)

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    
    # 1. Run ML & Heuristics Check (Primary System)
    analysis = await asyncio.to_thread(analyze_domain, domain, url)
    score = analysis.get('score', 0)
    
    is_safe = score < 50
    threat_level = analysis.get('risk', 'Unknown')
    reasons = analysis.get('details', [])
    
    # 2. Check Database for overrides (Secondary System)
    db_result = await search_url_in_all(url)
    if db_result:
        col = db_result["collection"]
        doc = db_result["document"]
        if col == "safe_urls":
            is_safe = True
            score = 0
            threat_level = 'Safe'
            reasons.append('ปลอดภัย (ตรวจสอบจากฐานข้อมูลระบบ Whitelist)')
        else:
            is_safe = False
            score = 100
            threat_level = doc.get('threat_level', 'High')
            reasons.append(f"อันตราย! ตรวจพบในฐานข้อมูล Blacklist (Source: {doc.get('source', 'DB')})")

    response = {
        'status': 'safe' if is_safe else 'danger',
        'site_name': domain,
        'message': 'ตรวจสอบเรียบร้อย' if is_safe else 'ตรวจพบสัญญาณอันตราย',
        'risk_score': score,
        'details': {
            'threat_level': threat_level,
            'category': 'Phishing / Scam' if not is_safe else 'Safe',
            'target_brand': 'Unknown',
            'official_url': None,
            'reasons': reasons
        }
    }
    return response

# ==== CHATBOT ENDPOINTS ====
@router.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse(request=request, name='chat.html')

@router.post("/chat")
async def chat_post(request: Request):
    message = None
    if request.headers.get("Content-Type") == "application/json":
        data = await request.json()
        message = data.get("message")
    else:
        form = await request.form()
        message = form.get("message")

    if not message or not isinstance(message, str):
        return JSONResponse({'error': 'No message provided'}, status_code=400)

    # Simplified chat: no session-based history for now
    # pyrefly: ignore [bad-argument-type]
    ai_response_raw = await asyncio.to_thread(get_ai_response, message, [])
    
    # Check if the raw response is an error JSON generated by brain.py
    import json
    try:
        parsed_raw = json.loads(ai_response_raw)
        if "error" in parsed_raw:
            return parsed_raw
    except:
        pass
        
    analysis = extract_json(ai_response_raw)
    
    if analysis and "analysis_result" in analysis:
        return {
            "response": ai_response_raw,
            "analysis_result": analysis["analysis_result"]
        }
    else:
        return {
            "response": ai_response_raw,
            "analysis_result": None
        }
# ==== ADMIN SYSTEM ====

def decode_google_email(token: str) -> str:
    try:
        # Simple JWT decode for email (not verified for production but fits the prompt's simplicity)
        payload_b64 = token.split('.')[1]
        missing_padding = len(payload_b64) % 4
        if missing_padding:
            payload_b64 += '=' * (4 - missing_padding)
        payload = json.loads(base64.b64decode(payload_b64).decode('utf-8'))
        return payload.get('email', '')
    except Exception:
        return ""

async def get_current_admin(request: Request):
    admin_email = request.cookies.get("admin_session")
    if not admin_email:
        return None
    return await get_admin_by_email(admin_email)

@router.get("/admin/login", response_class=HTMLResponse)
async def admin_login_get(request: Request):
    # If already logged in, redirect to dashboard
    admin = await get_current_admin(request)
    if admin:
        return RedirectResponse(url="/admin/dashboard")

    response = templates.TemplateResponse(request=request, name="admin_login.html", context={
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
    })
    # Security: Ensure login page is never cached
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response

@router.post("/admin/login")
async def admin_login_post(request: Request, response: Response):
    data = await request.json()
    google_token = data.get("google_token")
    password = data.get("password")

    email = decode_google_email(google_token)
    if not email:
        return JSONResponse({"error": "Invalid Google Identity"}, status_code=401)

    admin = await get_admin_by_email(email)
    if not admin or not verify_password(password, admin['password']):
        return JSONResponse({"error": "Unauthorized: Invalid Email or Password"}, status_code=401)

    # Set session cookie (simple version)
    response = JSONResponse({"status": "ok"})
    response.set_cookie(key="admin_session", value=email, httponly=True, max_age=3600*8)
    return response

@router.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    admin: Optional[dict] = await get_current_admin(request)
    if not admin:
        return RedirectResponse(url="/admin/login")

    reports = await get_recent_reports(limit=50)
    
    admins = []
    if admin['role'] == 'super_admin':
        admins = await list_admins()

    response = templates.TemplateResponse(request=request, name="admin_dashboard.html", context={
        "admin": admin,
        "reports": reports,
        "admins": admins
    })
    # Security: Prevent browser caching to avoid back-button access after logout
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response

@router.post("/admin/review")
async def admin_review(request: Request):
    admin = await get_current_admin(request)
    if not admin:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    data = await request.json()
    report_id = data.get("report_id")
    action = data.get("action") # approve | reject
    note = data.get("note")

    report = await get_report_by_id(report_id)
    if not report:
        return JSONResponse({"error": "Report not found"}, status_code=404)

    if action == "approve_safe":
        # Manually approved as Safe
        url = str(report.get('url', ''))
        domain = str(urlparse(url).netloc or url)
        # pyrefly: ignore [bad-argument-type]
        await add_safe_url(url, domain, category="Approved by Admin", source=f"admin:{admin['username']}")
        await update_report_status(report_id, "resolved", reviewer_note="Manually Approved as SAFE")
        
    elif action == "approve_phishing":
        # Manually approved as Phishing
        url = str(report.get('url', ''))
        domain = str(urlparse(url).netloc or url)
        # pyrefly: ignore [bad-argument-type]
        await add_phishing_url(url, domain, threat_level="high", source=f"admin:{admin['username']}")
        await update_report_status(report_id, "resolved", reviewer_note="Manually Approved as PHISHING")

    elif action == "approve":
        # Legacy/Automatic behavior
        url = str(report.get('url', ''))
        type = report.get('type')
        domain = str(urlparse(url).netloc or url)
        
        if type == "safe":
            # pyrefly: ignore [bad-argument-type]
            await add_safe_url(url, domain, category="Approved by Admin", source=f"admin:{admin['username']}")
        elif type == "phishing" or type == "fake_web" or type == "sms" or type == "email":
            # pyrefly: ignore [bad-argument-type]
            await add_phishing_url(url, domain, threat_level="high", source=f"admin:{admin['username']}")
        else:
            # pyrefly: ignore [bad-argument-type]
            await add_fake_url(url, domain, description="Approved suspect", source=f"admin:{admin['username']}")
        
    else:
        # Delete report completely from database on Reject
        await delete_report(report_id)

    return {"status": "ok"}

@router.post("/admin/manage")
async def admin_manage(request: Request):
    admin = await get_current_admin(request)
    if not admin or admin['role'] != 'super_admin':
        return JSONResponse({"error": "Forbidden: Super Admin access required"}, status_code=403)

    data = await request.json()
    action = data.get("action")

    if action == "add":
        new_email = data.get("new_email")
        new_username = data.get("new_username")
        new_password = data.get("new_password")
        new_role = data.get("new_role", "admin")
        if await add_admin(new_email, new_username, new_password, role=new_role):
            return {"status": "ok"}
        return JSONResponse({"error": "Failed to add admin (User might exist)"}, status_code=400)
    
    elif action == "delete":
        delete_email = data.get("delete_email")
        if delete_email == admin['email']:
            return JSONResponse({"error": "Cannot delete self"}, status_code=400)
        if await delete_admin(delete_email):
            return {"status": "ok"}
        return JSONResponse({"error": "Search failed or User not found"}, status_code=404)

    return JSONResponse({"error": "Invalid action"}, status_code=400)

@router.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin/login")
    response.delete_cookie("admin_session")
    return response
