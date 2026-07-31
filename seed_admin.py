import os
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from passlib.context import CryptContext
import sys

# Setup password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def seed_admin():
    load_dotenv()
    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri:
        print("Error: MONGODB_URI not found in .env")
        return

    client = AsyncIOMotorClient(mongo_uri)
    db = client.get_default_database()
    admins = db.admins

    # Check if sakchai already exists
    existing = await admins.find_one({"email": "sakchai.te@psru.ac.th"})
    if existing:
        print("Super Admin already exists. Updating password/role...")
        await admins.update_one(
            {"email": "sakchai.te@psru.ac.th"},
            {"$set": {
                "username": "sakchai",
                "password": pwd_context.hash("sakchai2004"),
                "role": "super_admin"
            }}
        )
    else:
        print("Creating Super Admin sakchai...")
        await admins.insert_one({
            "email": "sakchai.te@psru.ac.th",
            "username": "sakchai",
            "password": pwd_context.hash("sakchai2004"),
            "role": "super_admin"
        })
    
    print("Admin seeding completed.")
    client.close()

if __name__ == "__main__":
    # Fix for Windows asyncio loop policy
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(seed_admin())
