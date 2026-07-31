# 🛡️ คู่มือการรันโปรเจกต์ Jerb Cyber Phishing (FastAPI)

โปรเจกต์นี้เป็นระบบตรวจสอบ Phishing และแจ้งเบาะแส ซึ่งใช้ **FastAPI** เป็น Backend และมีการยืนยันตัวตนด้วย **Google OAuth**

---

## 🛠️ 1. สิ่งที่ต้องมีในเครื่อง (Prerequisites)
1.  **Python 3.10 ขึ้นไป** (ตรวจสอบโดยใช้คำสั่ง `python --version`)
2.  **Git** (สำหรับการดึงโค้ด)
3.  **API Keys** (Gemini, Groq, VirusTotal)

---

## 🚀 2. ขั้นตอนการติดตั้ง (Setup)

### ขั้นตอนที่ 2.1: การเตรียม Virtual Environment
เราจะสร้าง "ห้องจำลอง" เพื่อไม่ให้ Library ของโปรเจกต์นี้ไปตีกับโปรเจกต์อื่น
1.  เปิด Terminal ใน VS Code (กด `Ctrl + @`)
2.  พิมพ์คำสั่ง:
    ```powershell
    python -m venv .venv
    ```
3.  เปิดใช้งานห้องจำลอง (Activate):
    ```powershell
    .\.venv\Scripts\activate
    ```
    *สังเกตว่าจะมีตัวอักษร `(.venv)` ขึ้นข้างหน้าบรรทัดพิมพ์*

### ขั้นตอนที่ 2.2: การติดตั้ง Library
รันคำสั่งนี้เพื่อดาวน์โหลดโค้ดที่จำเป็นทั้งหมดมาที่เครื่อง:
```powershell
pip install -r requirements.txt
```

---

## ⚙️ 3. การตั้งค่าระบบ (Configuration)

### ขั้นตอนที่ 3.1: สร้างไฟล์ความลับ (.env)
1.  สร้างไฟล์ใหม่ชื่อ `.env` ไว้ในโฟลเดอร์หลัก
2.  ก๊อปปี้ข้อความด้านล่างนี้ไปใส่ และเปลี่ยนค่าให้เป็น API Key ของคุณ:
    ```env
    GEMINI_API_KEY=AIzaSy... (เอามาจาก Google AI Studio)
    GROQ_API_KEY=gsk_... (เอามาจาก Groq Console)
    VIRUSTOTAL_API_KEY=... (เอามาจาก VirusTotal)
    FLASK_SECRET_KEY=เลือก_Password_อะไรก็ได้ยาวๆ
    ```

### ขั้นตอนที่ 3.2: ตั้งค่า Google OAuth (เพื่อให้ปุ่ม Login ทำงาน)
1.  ไปที่ [Google Cloud Console](https://console.cloud.google.com/)
2.  เลือกโปรเจกต์ของคุณ -> **Credentials**
3.  แก้ไข **OAuth 2.0 Client ID**
4.  ในส่วน **Authorized JavaScript origins** ต้องมี:
    - `http://localhost:5000`
    - `http://127.0.0.1:5000`
5.  ก๊อปปี้ **Client ID** มาใส่ในไฟล์ `templates/report.html` และ `templates/detect_fb.html`

---

## 🏃 4. การรันโปรเจกต์ (Running)

รันคำสั่งนี้ใน Terminal:
```powershell
python main.py
```

### เมื่อรันแล้วจะเกิดอะไรขึ้น?
1.  หน้าจอจะขึ้นว่า `Application startup complete.`
2.  แอปจะรันอยู่ที่: `http://127.0.0.1:5000`
3.  กด **Ctrl + คลิก** ที่ลิงก์นั้นเพื่อเปิดหน้าเว็บ

---

## 📂 โครงสร้างโปรเจกต์ที่สำคัญ
-   `main.py`: จุดเริ่มต้นของโปรแกรม
-   `app/routes.py`: จุดควบคุมหน้าเว็บและ API ทั้งหมด
-   `templates/`: โฟลเดอร์เก็บไฟล์ HTML (หน้าตาเว็บ)
-   `static/`: โฟลเดอร์เก็บ CSS และ JavaScript (การตกแต่งและลูกเล่น)
-   `phishing_db.sqlite`: ฐานข้อมูลเก็บรายชื่อเว็บอันตราย (สร้างให้อัตโนมัติเมื่อรันครั้งแรก)

---

## 🆘 พบปัญหา?
-   **Error: "uvicorn" is not recognized:** ให้เช็คว่าได้รัน `pip install -r requirements.txt` หรือยัง
-   **Error: 401: invalid_client:** ให้เช็คว่าเอา Client ID ของ Google มาใส่หรือยัง
-   **Error: 400: origin_mismatch:** ให้เช็คว่าได้เพิ่ม `http://127.0.0.1:5000` ในหน้า Google Console หรือยัง
