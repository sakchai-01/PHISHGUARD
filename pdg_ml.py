# pdg_ml.py - Cleaned version

import os
import sqlite3
import pandas as pd # type: ignore
import numpy as np # type: ignore
import re

# ==========================================
# 1. Configuration & Constants
# ==========================================
DB_PATH = '/content/phishing_db.sqlite'
# Assuming we need a local fallback since /content/ is colab
if not os.path.exists(DB_PATH):
    DB_PATH = 'phishing_db.sqlite'

KNOWN_BAD_URLS = [
    'download5000.com', 'thaigrowthdigitalmarketing.cc', 'settradethailand.com',
    'ezbuy66.com', 'trade-thai.com', 'hsgi.xyz', 'btscswl.com', 'happinessco.cc',
    'erwz.live', 'tokts.life', 'thaibet248.com', 'thaipvz.com', 'shopping-now-maket.com',
    'pi-moneyloan.com', 'bjgth.cc', 'cryptoxj.com', 'bonanza-store.net', 'hshh-banktt.app',
    'royaltrad.vip', 'astalavista.box.sk', 'crack.ms', 'seriall.com', 'serialz.to'
]

# ==========================================
# 2. Feature Extraction & Prediction Engine
# ==========================================

def extract_features(url):
    """สกัดคุณลักษณะของ URL เพื่อใช้ในระบบ Heuristic และ RL"""
    features = [
        len(url),                   # ความยาว
        url.count('.'),             # จำนวนจุด
        1 if '@' in url else 0,     # มี @ หรือไม่
        url.count('-'),             # จำนวนขีด
        1 if 'https' in url else 0  # มี https หรือไม่
    ]
    return np.array(features)

def predict_risk(url):
    """วิเคราะห์ความเสี่ยงของ URL ด้วยกฎ Heuristic และ Blacklist"""
    url = url.lower().replace(' ', '')
    score = 0
    reasons = []

    # 1. Blacklist Check
    for bad_url in KNOWN_BAD_URLS:
        if bad_url in url:
            score += 100
            reasons.append(f'ตรวจพบใน Blacklist: {bad_url}')
            break

    if score < 100:
        # 2. Heuristic Rules (Suspicious Words)
        suspicious_words = ['download', 'free', 'update', 'login', 'verify', 'account', 'banking', 'trade', 'loan', 'money']
        for word in suspicious_words:
            if word in url:
                score += 30
                reasons.append(f'พบคำเสี่ยง: {word}')

        # 3. Bad TLDs
        bad_tlds = ['.xyz', '.cc', '.live', '.vip', '.top', '.app', '.tk', '.ga']
        for tld in bad_tlds:
            if url.endswith(tld) or f'{tld}/' in url:
                score += 35
                reasons.append(f'นามสกุลโดเมนเสี่ยงสูง: {tld}')

        # 4. Digits in Domain
        domain = url.split('/')[0] if '/' in url else url
        if sum(c.isdigit() for c in domain) > 3:
            score += 25
            reasons.append('ชื่อโดเมนมีตัวเลขมากผิดปกติ')

    # Result calculation
    if score >= 60:
        risk_level, status = "High", "Dangerous"
    elif score >= 30:
        risk_level, status = "Medium", "Warning"
    else:
        risk_level, status = "Low", "Safe"

    return min(score, 100), risk_level, status, reasons

# ==========================================
# 3. Reinforcement Learning (Q-Learning)
# ==========================================

class URLRiskEnv:
    def __init__(self, data):
        self.data = data
        self.n_samples = len(data)
        self.current_idx = 0

    def reset(self):
        self.current_idx = 0
        return extract_features(self.data.iloc[self.current_idx]['url'])

    def step(self, action):
        actual_risk = 1 if self.data.iloc[self.current_idx]['risk_score'] > 50 else 0
        reward = 1 if action == actual_risk else -1

        self.current_idx += 1
        done = self.current_idx >= self.n_samples
        next_state = extract_features(self.data.iloc[self.current_idx]['url']) if not done else None

        return next_state, reward, done

def train_rl_model(db_path=DB_PATH):
    try:
        conn = sqlite3.connect(db_path)
        df = pd.read_sql_query("SELECT url, risk_score FROM phishing_urls", conn)
        
        alpha, gamma, epsilon = 0.1, 0.9, 0.1
        q_table = {}

        def get_q_state(features): return tuple(features)
        
        def choose_action(state_key):
            if np.random.uniform(0, 1) < epsilon:
                return np.random.choice([0, 1])
            return np.argmax(q_table.get(state_key, [0, 0]))

        env = URLRiskEnv(df)
        for episode in range(min(1000, len(df))):
            state = env.reset()
            done = False
            while not done:
                state_key = get_q_state(state)
                if state_key not in q_table: q_table[state_key] = [0.0, 0.0]

                action = choose_action(state_key)
                next_state, reward, done = env.step(action)

                if not done:
                    next_key = get_q_state(next_state)
                    if next_key not in q_table: q_table[next_key] = [0.0, 0.0]
                    old_value = q_table[state_key][action]
                    next_max = np.max(q_table[next_key])
                    q_table[state_key][action] = old_value + alpha * (reward + gamma * next_max - old_value)
                    state = next_state
        print(f"✅ RL Training complete. Q-Table size: {len(q_table)}")
    except Exception as e:
        print(f"⚠️ Could not train RL model: {e}")

# ==========================================
# 4. Generate Web Assets (app.py, index.html)
# ==========================================

APP_PY_CONTENT = """import os
from flask import Flask, request, jsonify

app = Flask(__name__)

KNOWN_BAD_URLS = [
    'download5000.com', 'thaigrowthdigitalmarketing.cc', 'settradethailand.com',
    'ezbuy66.com', 'trade-thai.com', 'hsgi.xyz', 'btscswl.com', 'happinessco.cc',
    'erwz.live', 'tokts.life', 'thaibet248.com', 'thaipvz.com', 'shopping-now-maket.com',
    'pi-moneyloan.com', 'bjgth.cc', 'cryptoxj.com', 'bonanza-store.net', 'hshh-banktt.app',
    'royaltrad.vip', 'astalavista.box.sk', 'crack.ms', 'seriall.com', 'serialz.to'
]

def predict_risk(url):
    url = url.lower().replace(' ', '')
    score = 0
    reasons = []

    for bad_url in KNOWN_BAD_URLS:
        if bad_url in url:
            score += 100
            reasons.append(f'ตรวจพบใน Blacklist: {bad_url}')
            break

    if score < 100:
        suspicious_words = ['download', 'free', 'update', 'login', 'verify', 'account', 'banking', 'trade', 'loan', 'money']
        for word in suspicious_words:
            if word in url:
                score += 30
                reasons.append(f'พบคำเสี่ยงต่อการหลอกลวง: {word}')

        bad_tlds = ['.xyz', '.cc', '.live', '.vip', '.top', '.app', '.tk', '.ga']
        for tld in bad_tlds:
            if url.endswith(tld) or f'{tld}/' in url:
                score += 35
                reasons.append(f'ใช้นามสกุลโดเมนที่มีความเสี่ยงสูง: {tld}')

        domain = url.split('/')[0] if '/' in url else url
        if sum(c.isdigit() for c in domain) > 3:
            score += 25
            reasons.append('ชื่อโดเมนมีตัวเลขปนอยู่มากผิดปกติ')

    if score >= 60:
        risk_level, status = "High", "Dangerous"
    elif score >= 30:
        risk_level, status = "Medium", "Warning"
    else:
        risk_level, status = "Low", "Safe"

    return min(score, 100), risk_level, status, reasons

@app.route('/')
def index():
    try:
        with open('index.html', 'r') as f: return f.read()
    except:
        return "<h1>Ready. index.html not found.</h1>"

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '')
    if not url: return jsonify({'error': 'No URL'}), 400

    score, risk, status, reasons = predict_risk(url)
    return jsonify({
        'url': url,
        'risk_score': score,
        'risk_level': risk,
        'status': status,
        'reasons': reasons
    })

if __name__ == '__main__':
    app.run(debug=True)
"""

INDEX_HTML_CONTENT = """<!DOCTYPE html>
<html>
<head>
    <title>URL Risk AI Analyzer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .risk-High { color: #dc3545; font-weight: bold; }
        .risk-Medium { color: #fd7e14; }
        .risk-Low { color: #198754; }
    </style>
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card shadow-lg border-0">
                    <div class="card-header bg-primary text-white">
                        <h3 class="mb-0">AI URL Risk Analyzer (Enhanced)</h3>
                    </div>
                    <div class="card-body p-4">
                        <p class="text-muted">ใส่ URL เพื่อวิเคราะห์ความเสี่ยงด้วยระบบ Heuristic & RL</p>
                        <div class="input-group mb-3">
                            <input type="text" id="urlInput" class="form-control form-control-lg" placeholder="เช่น www.download5000.com">
                            <button onclick="analyze()" class="btn btn-primary btn-lg">ตรวจสอบ</button>
                        </div>
                        <div id="result" class="mt-4" style="display:none;">
                            <div class="alert" id="alertBox">
                                <h4 id="statusText"></h4>
                                <hr>
                                <p><strong>Risk Score:</strong> <span id="scoreText"></span>/100</p>
                                <p><strong>Risk Level:</strong> <span id="levelText"></span></p>
                                <div id="reasonsSection">
                                    <strong>เหตุผลที่พบ:</strong>
                                    <ul id="reasonsList"></ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script>
        async function analyze() {
            const url = document.getElementById('urlInput').value;
            const resultDiv = document.getElementById('result');
            const alertBox = document.getElementById('alertBox');

            if(!url) return alert('กรุณากรอก URL');

            const res = await fetch('/analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url})
            });
            const data = await res.json();

            resultDiv.style.display = 'block';
            document.getElementById('statusText').innerText = data.status === 'Dangerous' ? '⚠️ ตรวจพบความเสี่ยง!' : '✅ ปลอดภัยเบื้องต้น';
            document.getElementById('scoreText').innerText = data.risk_score;
            document.getElementById('levelText').innerText = data.risk_level;
            document.getElementById('levelText').className = 'risk-' + data.risk_level;

            alertBox.className = 'alert ' + (data.status === 'Dangerous' ? 'alert-danger' : 'alert-success');

            const list = document.getElementById('reasonsList');
            list.innerHTML = '';
            if(data.reasons && data.reasons.length > 0) {
                data.reasons.forEach(r => {
                    const li = document.createElement('li');
                    li.innerText = r;
                    list.appendChild(li);
                });
            } else {
                list.innerHTML = '<li>ไม่พบรูปแบบที่น่าสงสัยชัดเจน</li>';
            }
        }
    </script>
</body>
</html>
"""

REQUIREMENTS_CONTENT = "flask\nnumpy\npandas\n"
VERCEL_JSON_CONTENT = '{"version": 2, "builds": [{"src": "app.py", "use": "@vercel/python"}], "routes": [{"src": "/(.*)", "dest": "app.py"}]}'

def generate_deployment_files():
    """สร้างไฟล์ app.py, index.html, requirements.txt, และ vercel.json"""
    files = {
        'app.py': APP_PY_CONTENT,
        'index.html': INDEX_HTML_CONTENT,
        'requirements.txt': REQUIREMENTS_CONTENT,
        'vercel.json': VERCEL_JSON_CONTENT
    }
    
    for filename, content in files.items():
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✅ สร้างไฟล์ {filename} เรียบร้อยแล้ว")

# ==========================================
# 5. Main Execution
# ==========================================
if __name__ == "__main__":
    print("🚀 เริ่มการทำงาน...")
    
    # 1. ทดสอบระบบทำนายความเสี่ยง (Prediction Engine)
    print("\n--- ทดสอบการวิเคราะห์ URL ---")
    test_urls = [
        "https://www.google.com",
        "free-money-loan.xyz",
        "download5000.com",
        "update-your-account-banking.net",
        "my-login-site-12345.com"
    ]
    for url in test_urls:
        s, l, st, r = predict_risk(url)
        print(f"{url:<35} | {s:<5} | {l:<10} | {st}")

    # 2. ทำการฝึกสอน RL Model (ถ้ามีฐานข้อมูล)
    print("\n--- เริ่มกระบวนการ RL Training ---")
    train_rl_model()

    # 3. สร้างไฟล์สำหรับการ Deployment (Flask & Vercel)
    print("\n--- สร้างไฟล์เว็บแอปพลิเคชัน ---")
    generate_deployment_files()
    
    print("\n🎉 การรันสคริปต์เสร็จสมบูรณ์!")