from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
import os

from app.db.session import get_db
from app.services.report_service import ReportService
from app.repositories.admin_repo import AdminRepository

router = APIRouter(prefix="/admin", tags=["admin"])
_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
templates = Jinja2Templates(directory=os.path.join(_BASE, "templates"))

async def get_current_admin(request: Request, db: AsyncSession = Depends(get_db)):
    email = request.cookies.get("admin_session")
    if not email:
        raise HTTPException(status_code=401, detail="Not authenticated")
    repo = AdminRepository(db)
    admin = await repo.get_by_email(email)
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid admin session")
    return admin

@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request, admin=Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    report_service = ReportService(db)
    reports = await report_service.get_recent_reports(status="new", limit=50)
    
    # We can fetch admins if they are a super_admin
    admins = []
    if admin.role == "super_admin":
        repo = AdminRepository(db)
        admins = await repo.list_admins()
        
    response = templates.TemplateResponse(request=request, name="admin_dashboard.html", context={
        "admin": admin,
        "reports": reports,
        "admins": admins
    })
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response
