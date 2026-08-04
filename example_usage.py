"""
example_usage.py - ตัวอย่างการเรียกใช้ 3-Layer Phishing Guard Engine
"""

import json
from app.domain_checker import quick_check, extract_features, check_url_full
import pdg_ml

def main():
    test_urls = [
        "https://www.kasikornbank.com",
        "http://192.168.1.50/@login",
        "http://kbank-verify-account.tk",
        "http://scbb-online.ga"
    ]
    
    print("==================================================")
    print("🛡️ 3-Layer Phishing Guard Demo")
    print("==================================================\n")
    
    for url in test_urls:
        print(f"🔗 Testing URL: {url}")
        
        # Layer 1: Quick Check
        q_res = quick_check(url)
        print(f"  └─ Layer 1 Quick Check Score: {q_res['score']}/100 (Reasons: {q_res['reasons']})")
        
        # Layer 2 & 3 & Ensemble: Full Check
        full_res = check_url_full(url)
        print("  └─ Full Ensemble Result:")
        print(json.dumps(full_res, indent=4, ensure_ascii=False))
        print("-" * 50)

if __name__ == "__main__":
    main()
