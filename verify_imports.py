import sys
import os

# Add current directory to sys.path to simulate how the app runs
sys.path.append(os.getcwd())

modules_to_test = [
    "fastapi",
    "uvicorn",
    "dotenv",
    "google.generativeai",
    "app.routes",
    "app.core.database",
    "app.core.compat",
    "app.brain"
]

print("--- Import Verification ---")
success_count = 0
for module in modules_to_test:
    try:
        __import__(module)
        print(f"✅ {module}: Imported successfully")
        success_count += 1
    except ImportError as e:
        print(f"❌ {module}: Import failed - {e}")
    except Exception as e:
        print(f"⚠️ {module}: Error during import - {e}")

print(f"\nSummary: {success_count}/{len(modules_to_test)} modules imported successfully.")

if success_count == len(modules_to_test):
    sys.exit(0)
else:
    sys.exit(1)
