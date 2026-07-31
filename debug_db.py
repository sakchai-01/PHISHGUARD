import os
from dotenv import load_dotenv
from pymongo import MongoClient
import sys

def check():
    load_dotenv()
    uri = os.getenv('MONGODB_URI')
    db_name = os.getenv('MONGODB_DB_NAME', 'pdg_db')
    
    print(f"Connecting to MongoDB URI: {uri[:20] if uri else 'None'}...")
    print(f"Using Database: {db_name}")
    
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        db = client[db_name]
        
        # List all collections to see what we have
        collections = db.list_collection_names()
        print(f"Collections in {db_name}: {collections}")
        
        if 'admins' not in collections:
            print("WARNING: 'admins' collection NOT found.")
            # Let's check 'test' database too just in case
            test_db = client['test']
            print(f"Collections in 'test': {test_db.list_collection_names()}")
        
        admin = db.admins.find_one({'email': 'sakchai.te@psru.ac.th'})
        if admin:
            print(f"SUCCESS: Found admin {admin['username']} with email {admin['email']}")
            print(f"Role: {admin.get('role')}")
        else:
            print("FAILURE: Admin record for 'sakchai.te@psru.ac.th' NOT found.")
            
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    check()
