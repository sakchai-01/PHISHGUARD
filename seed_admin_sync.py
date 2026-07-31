import os
from pymongo import MongoClient
from dotenv import load_dotenv
from passlib.context import CryptContext
import sys

# Setup password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def seed_admin():
    load_dotenv()
    mongo_uri = os.getenv("MONGODB_URI")
    if not mongo_uri:
        print("Error: MONGODB_URI not found in .env")
        return

    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        # Force a connection check
        client.admin.command('ping')
        db = client['pdg_db']
        admins = db.admins

        # Check if sakchai already exists
        existing = admins.find_one({"email": "sakchai.te@psru.ac.th"})
        if existing:
            print("Super Admin already exists. Updating password/role...")
            admins.update_one(
                {"email": "sakchai.te@psru.ac.th"},
                {"$set": {
                    "username": "sakchai",
                    "password": pwd_context.hash("sakchai2004"),
                    "role": "super_admin"
                }}
            )
        else:
            print("Creating Super Admin sakchai...")
            admins.insert_one({
                "email": "sakchai.te@psru.ac.th",
                "username": "sakchai",
                "password": pwd_context.hash("sakchai2004"),
                "role": "super_admin"
            })
        
        print("Admin seeding completed.")
        client.close()
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    seed_admin()
