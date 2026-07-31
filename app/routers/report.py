from fastapi import APIRouter, Depends, Form, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
import os

from app.db.session import get_db
from app.services.report_service import ReportService
from app.schemas.report import ReportCreate
from app.core.config import settings

router = APIRouter(prefix="/report", tags=["report"])
_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
templates = Jinja2Templates(directory=os.path.join(_BASE, "templates"))

@router.get("/", response_class=HTMLResponse)
async def report_get(request: Request):
    return templates.TemplateResponse(request=request, name="report.html", context={
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
    })

@router.post("/", response_class=HTMLResponse)
async def report_post(
    request: Request,
    email: str = Form(...),
    url: str = Form(...),
    description: str = Form(None),
    type: str = Form("other"),
    db: AsyncSession = Depends(get_db)
):
    try:
        service = ReportService(db)
        report_data = ReportCreate(email=email, type=type, url=url, description=description) # type: ignore
        report = await service.submit_report(report_data)
        
        return templates.TemplateResponse(request=request, name="report.html", context={
            "success": f"ขอบคุณสำหรับการแจ้งเบาะแสคุณ {email}! รหัสอ้างอิง: {report.id}",
            "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
        })
    except Exception as e:
        return templates.TemplateResponse(request=request, name="report.html", context={
            "error": f"เกิดข้อผิดพลาด: {str(e)}",
            "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
        })
