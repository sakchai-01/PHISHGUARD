from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
import os

from app.db.session import get_db
from app.services.auth_service import AuthService
from app.core.security import create_access_token
from app.schemas.admin import Token

router = APIRouter(prefix="/auth", tags=["auth"])
_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
templates = Jinja2Templates(directory=os.path.join(_BASE, "templates"))

@router.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    if request.cookies.get("admin_session"):
        return RedirectResponse(url="/admin/dashboard")
    response = templates.TemplateResponse(request=request, name="admin_login.html", context={
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
    })
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response

@router.post("/login")
async def login_post(request: Request, db: AsyncSession = Depends(get_db)):
    data = await request.json()
    google_token = data.get("google_token")
    
    auth_service = AuthService(db)
    user = await auth_service.authenticate_google(google_token)
    
    if not user:
        return JSONResponse({"error": "Unauthorized: Invalid Google Identity or Not Registered"}, status_code=401)
    
    # Normally use JWT, but matching legacy cookie-based for now
    # We could also use create_access_token if transitioning to pure API
    response = JSONResponse({"status": "ok"})
    response.set_cookie(key="admin_session", value=str(user.email), httponly=True, max_age=3600*8)
    return response

@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/auth/login")
    response.delete_cookie("admin_session")
    return response
