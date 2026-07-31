import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.db.init_db import init_db
from app.routers import scan
# Legacy routes for now to keep things working during transition
from app.routes import router as legacy_router

# Only apply Windows patches when running locally on Windows
if os.name == 'nt':
    try:
        from app.core.compat import apply_windows_patches
        apply_windows_patches()
    except Exception:
        pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLAlchemy DB
    try:
        await init_db()
    except Exception as e:
        print(f"⚠️ DB init skipped or failed: {e}")
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="ASync FastAPI Backend for Phishing Detection",
    version="2.0.0",
    docs_url=None if os.getenv("ENVIRONMENT") == "production" else "/docs",
    redoc_url=None if os.getenv("ENVIRONMENT") == "production" else "/redoc",
    lifespan=lifespan
)

# CORS Support
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://accounts.google.com https://cdn.tailwindcss.com "
        "https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
        "https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://pdg-wheat.vercel.app; "
        "frame-src https://accounts.google.com; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
    return response

# Static Files
STATIC_DIR = os.path.join(settings.PROJECT_ROOT, "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# New Modular Routers (5-Layer Architecture)
from app.routers import scan, report, chat

app.include_router(scan.router, prefix=settings.API_V1_STR)
app.include_router(report.router)
# app.include_router(auth.router)  # Disabled: using legacy MongoDB auth route
# app.include_router(admin.router) # Disabled: using legacy MongoDB admin route
app.include_router(chat.router)

# Legacy Router (MongoDB Backend for Auth & Admin Dashboard)
app.include_router(legacy_router)


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 5000))
    uvicorn.run("main:app", host=host, port=port, reload=True, reload_includes=["*.html", "*.css", "*.js"])
