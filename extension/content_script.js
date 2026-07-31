// content_script.js - Real-time page scanner

console.log("🛡️ Janis AI Cyber Guardian Active");

// 1. Initial URL Scan
const currentUrl = window.location.href;
if (!currentUrl.startsWith("chrome://") && !currentUrl.startsWith("about:")) {
    showStatusToast("🔍 Janis AI: กำลังตรวจสอบ URL...");
    if (chrome.runtime && chrome.runtime.id) {
        chrome.runtime.sendMessage({ action: "scanUrl", url: currentUrl }, (response) => {
            if (chrome.runtime.lastError) {
                console.warn("Janis AI: Connection lost (Extension reloaded). Please refresh the page.");
                return;
            }
            if (response && response.status === "danger") {
                showAlert(`⚠️ คำเตือนจาก JANIS AI: เว็บไซต์นี้ (${response.site_name}) ถูกระบุว่าเป็นความเสี่ยงระดับ ${response.details.threat_level}!`, "danger");
            } else if (response && response.error) {
                console.error("Janis AI Scan Error:", response.error);
            } else {
                console.log("✅ Janis AI: URL is safe.");
            }
        });
    }
}

// 2. Content Scan (Debounced for performance)
let scanTimeout;
let lastScannedUrl = "";

function scanPageContent() {
    const currentUrl = window.location.href;
    const pageText = document.body.innerText;
    
    // Rule: Don't scan again if already scanned for this exact URL load
    if (lastScannedUrl === currentUrl) return;

    // Detect if this is likely a chat or message interface
    const isChat = detectChatInterface();
    
    if (isChat) {
        console.log("🛡️ Janis AI: Chat interface detected. Waiting for user permission...");
        showPermissionToast();
        return;
    }

    executeScan();
}

function detectChatInterface() {
    // Keywords in classes/ids or presence of common chat structures
    const chatSelectors = ['[class*="chat"]', '[class*="message"]', '[id*="chat"]', 'textarea', '[contenteditable="true"]'];
    const hasChatElements = chatSelectors.some(sel => document.querySelector(sel) !== null);
    
    // Check if the URL suggests a chat app
    const chatUrls = ['facebook.com/messages', 'messenger.com', 'web.whatsapp.com', 'line.me', 'slack.com'];
    const isChatUrl = chatUrls.some(u => window.location.href.includes(u));

    return hasChatElements || isChatUrl;
}

function executeScan(immediate = false) {
    const pageText = document.body.innerText;
    
    // Expand keywords for better coverage
    const keywords = [
        "login", "password", "bank", "credit card", "verify", "account", "secure", "threat", "scam",
        "ธนาคาร", "รหัสผ่าน", "โอนเงิน", "บัญชี", "ลงชื่อเข้าใช้", "วอลเล็ต", "ยืนยันตัวตน", 
        "ตรวจสอบ", "ถูกระงับ", "เตือน", "ภัย", "ความปลอดภัย", "รางวัล"
    ];
    const hasKeywords = keywords.some(k => pageText.toLowerCase().includes(k));

    if (!hasKeywords) return;

    const performAnalysis = () => {
        // Double check URL hasn't changed during wait (if not immediate)
        if (!immediate && lastScannedUrl === window.location.href) return;
        
        lastScannedUrl = window.location.href;
        console.log("🔍 Janis AI: Analyzing page content...");
        
        showStatusToast("🔍 Janis AI: กำลังวิเคราะห์เนื้อหา...", 2000);

        if (chrome.runtime && chrome.runtime.id) {
            chrome.runtime.sendMessage({ action: "analyzeText", text: document.body.innerText.substring(0, 5000) }, (response) => {
                if (chrome.runtime.lastError) return; // Silent fail if context invalidated
                if (response && response.analysis_result && response.analysis_result.is_scam) {
                    showAlert(`🚨 แจ้งเตือนจาก JANIS AI: พบภัยคุกคามที่อาจเกิดขึ้นบนหน้านี้: ${response.analysis_result.category}! \n\n${response.analysis_result.recommendation}`, "danger");
                }
            });
        }
    };

    if (immediate) {
        performAnalysis();
    } else {
        clearTimeout(scanTimeout);
        scanTimeout = setTimeout(performAnalysis, 8000);
    }
}

function showPermissionToast() {
    const id = "janis-permission-toast";
    if (document.getElementById(id)) return;

    const toast = document.createElement("div");
    toast.id = id;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #1e293b;
        color: white;
        padding: 16px 20px;
        border-radius: 12px;
        z-index: 999999;
        font-family: 'Kanit', sans-serif;
        box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        border-right: 5px solid #7c3aed;
        display: flex;
        flex-direction: column;
        gap: 12px;
        max-width: 300px;
        animation: janis-slide-in 0.5s ease-out;
    `;
    
    toast.innerHTML = `
        <div style="font-size: 14px; font-weight: 600;">🛡️ Janis AI Privacy Protection</div>
        <div style="font-size: 13px; color: #94a3b8; line-height: 1.4;">ตรวจพบช่องสนทนาหรือการกรอกข้อมูล ต้องการให้ Janis AI ช่วยตรวจสอบความปลอดภัยของข้อความนี้หรือไม่?</div>
        <div style="display: flex; gap: 8px;">
            <button id="janis-allow-scan" style="flex: 1; background: #7c3aed; color: white; border: none; padding: 6px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;">อนุญาต</button>
            <button id="janis-deny-scan" style="flex: 1; background: rgba(255,255,255,0.05); color: #94a3b8; border: 1px solid rgba(255,255,255,0.1); padding: 6px; border-radius: 6px; cursor: pointer; font-size: 12px;">ไม่ต้องการ</button>
        </div>
    `;
    document.body.appendChild(toast);

    document.getElementById("janis-allow-scan").onclick = () => {
        toast.remove();
        executeScan(true); // Scan immediately
    };
    document.getElementById("janis-deny-scan").onclick = () => {
        toast.remove();
        lastScannedUrl = window.location.href; // Mark as "processed" for this URL
    };
}

// Run initial scan and watch for changes (dynamic sites)
if (document.body) {
    scanPageContent();
    const observer = new MutationObserver((mutations) => {
        // Only trigger scan if relevant elements changed
        const relevantChange = mutations.some(m => m.type === 'childList' || m.type === 'characterData');
        if (relevantChange) scanPageContent();
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
}

function showStatusToast(message, duration = 3000) {
    const id = "janis-status-toast";
    let toast = document.getElementById(id);
    if (!toast) {
        toast = document.createElement("div");
        toast.id = id;
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            left: 20px;
            background: rgba(15, 23, 42, 0.9);
            color: #22d3ee;
            padding: 10px 20px;
            border-radius: 8px;
            z-index: 999998;
            font-family: 'Kanit', sans-serif;
            font-size: 12px;
            border-left: 3px solid #7c3aed;
            backdrop-blur: 10px;
            transition: opacity 0.3s;
        `;
        document.body.appendChild(toast);
    }
    toast.innerText = message;
    toast.style.opacity = "1";
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// Add animation style once
if (!document.getElementById("janis-styles")) {
    const style = document.createElement('style');
    style.id = "janis-styles";
    style.innerHTML = `
        @keyframes janis-slide-in {
            from { transform: translateX(120%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        .janis-alert-container {
            position: fixed;
            top: 20px;
            right: 20px;
            color: white;
            padding: 24px;
            border-radius: 16px;
            z-index: 999999;
            font-family: 'Kanit', sans-serif;
            box-shadow: 0 20px 50px rgba(0,0,0,0.5);
            max-width: 420px;
            animation: janis-slide-in 0.5s cubic-bezier(0.16, 1, 0.3, 1);
            display: flex;
            flex-direction: column;
        }
    `;
    document.head.appendChild(style);
}

let activeAlert = null;
let alertQueue = [];

function showAlert(message, type = "danger") {
    // Prevent duplicate entries in queue or active alert
    if (activeAlert && activeAlert.dataset.message === message) return;
    if (alertQueue.some(item => item.message === message)) return;

    if (activeAlert) {
        // If an alert is already showing, add the new one to the queue
        alertQueue.push({ message, type });
        return;
    }

    renderAlert(message, type);
}

function renderAlert(message, type) {
    const div = document.createElement("div");
    div.className = "janis-alert-container";
    div.dataset.message = message;
    const bgColor = type === "danger" ? "#ef4444" : "#10b981";
    div.style.background = bgColor;
    div.style.borderLeft = "8px solid rgba(255,255,255,0.3)";
    document.body.appendChild(div);
    activeAlert = div;

    div.innerHTML = `
        <div style="font-weight: 800; margin-bottom: 12px; font-size: 18px; letter-spacing: 1px; display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 24px;">🛡️</span> JANIS AI SHIELD
        </div>
        <div style="font-size: 15px; line-height: 1.6; white-space: pre-wrap;">${message}</div>
        <div style="margin-top: 20px; display: flex; gap: 10px;">
            <button class="janis-btn-close" style="flex: 1; background: white; color: ${bgColor}; border: none; padding: 10px; border-radius: 10px; cursor: pointer; font-weight: 800; text-transform: uppercase; font-size: 12px;">ฉันเข้าใจแล้ว</button>
            <button class="janis-btn-report" style="flex: 1; background: rgba(0,0,0,0.2); color: white; border: 1px solid rgba(255,255,255,0.2); padding: 10px; border-radius: 10px; cursor: pointer; font-weight: 600; font-size: 12px;">ไม่ใช่สแกม (รายงาน)</button>
        </div>
    `;

    div.querySelector(".janis-btn-close").onclick = () => {
        div.remove();
        activeAlert = null;
        showNextInQueue();
    };
    div.querySelector(".janis-btn-report").onclick = () => {
        alert("ส่งรายงานไปยัง Janis AI Lab แล้ว ขอบคุณครับ!");
        div.remove();
        activeAlert = null;
        showNextInQueue();
    };
}

function showNextInQueue() {
    if (alertQueue.length > 0) {
        const next = alertQueue.shift();
        renderAlert(next.message, next.type);
    }
}
