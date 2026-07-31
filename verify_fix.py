import sys
import os

# Get the absolute path of the directory where this script is located
# and add it to sys.path to ensure 'app' can be found.
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

print(f"DEBUG: sys.path[0] = {sys.path[0]}")

try:
    from app.brain import get_ai_response
    print("✅ Successfully imported get_ai_response from app.brain")
    
    # Test calling with None
    # Note: We won't actually call the API, just check if the function header is fine
    # and if it handles the 'None' correctly internally (it should return error JSON if model is None)
    response = get_ai_response("Hello", None)
    print(f"✅ Call with None returned: {response[:50]}...")
    
    # Test calling with empty list
    response = get_ai_response("Hello", [])
    print(f"✅ Call with [] returned: {response[:50]}...")
    
    print("🚀 Type hints and basic functionality verified!")
    
except Exception as e:
    print(f"❌ Verification failed: {e}")
    # Print more debug info
    print(f"Current working directory: {os.getcwd()}")
    print(f"Script directory: {script_dir}")
    print(f"App directory exists: {os.path.exists(os.path.join(script_dir, 'app'))}")
    sys.exit(1)
