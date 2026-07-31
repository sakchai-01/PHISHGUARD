import os
import asyncio
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext

load_dotenv()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def check():
    uri = os.getenv('MONGODB_URI')
    client = AsyncIOMotorClient(uri)
    # The default database might not be set in the URI
    db = client['phishing_db'] # Based on common pattern in this project
    admin = await db.admins.find_one({'email': 'sakchai.te@psru.ac.th'})
    
    if not admin:
        print("Admin NOT found in database.")
        return

    print(f"Admin found: {admin['username']} ({admin['email']})")
    print(f"Hashed password in DB: {admin['password']}")
    
    test_password = "sakchai2004"
    match = pwd_context.verify(test_password, admin['password'])
    print(f"Password 'sakchai2004' matches: {match}")

if __name__ == "__main__":
    asyncio.run(check())
