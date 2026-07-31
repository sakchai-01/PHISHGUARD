import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Jerb Cyber Phishing"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-super-secret-key-for-development-only")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    
    # CORS
    BACKEND_CORS_ORIGINS: list[str] = ["http://localhost:5000", "http://127.0.0.1:5000"]

    # Database (SQLite for now, ready for PostgreSQL)
    PROJECT_ROOT: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{os.path.join(PROJECT_ROOT, 'phishing_db_v2.sqlite')}")

    class Config:
        case_sensitive = True

settings = Settings()
