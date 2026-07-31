// background.js - Bridge between content script and Janis AI Backend

const API_BASE = "http://localhost:5000";

console.log("🚀 Janis AI Background Service Worker Initialized");

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log(`📩 Incoming Message: ${request.action}`, request);

  if (request.action === "scanUrl") {
    scanUrl(request.url)
      .then(res => {
        console.log("✅ Scan URL Result:", res);
        sendResponse(res);
      })
      .catch(err => {
        console.error("❌ Scan URL Error:", err);
        sendResponse({ error: "การสแกนล้มเหลว", details: err.message });
      });
    return true; 
  }

  if (request.action === "analyzeText") {
    analyzeText(request.text)
      .then(res => {
        console.log("✅ Analyze Text Result:", res);
        sendResponse(res);
      })
      .catch(err => {
        console.error("❌ Analyze Text Error:", err);
        sendResponse({ error: "การวิเคราะห์ล้มเหลว", details: err.message });
      });
    return true;
  }
});

async function scanUrl(url) {
  console.log(`🔍 Scanning URL: ${url}`);
  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error("⚠ Janis AI API Error (scan):", error);
    return { error: "การเชื่อมต่อล้มเหลว", details: error.message };
  }
}

async function analyzeText(text) {
  console.log(`📝 Analyzing Text (${text.length} chars)`);
  try {
    const response = await fetch(`${API_BASE}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        message: `วิเคราะห์ข้อความนี้อย่างละเอียดว่าเป็น Phishing หรืออันตรายหรือไม่: ${text.substring(0, 1500)}` 
      })
    });
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error("⚠ Janis AI API Error (chat):", error);
    return { error: "การเชื่อมต่อล้มเหลว", details: error.message };
  }
}
