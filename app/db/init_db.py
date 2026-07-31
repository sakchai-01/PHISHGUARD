import asyncio
from app.db.session import engine, Base
# Import all models here so that Base.metadata.create_all can discover them
from app.models.report import UserReport
from app.models.url_record import URLRecord
# Add other models as they are created

async def init_db():
    """
    Initialize all required tables.
    """
    async with engine.begin() as conn:
        # Create all tables (does not drop existing)
        await conn.run_sync(Base.metadata.create_all)
        print("[DB] SQLite (SQLAlchemy) initialized successfully.")

if __name__ == "__main__":
    asyncio.run(init_db())
