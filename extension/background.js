// background.js - Bridge between content script and Janis AI Backend

try {
  importScripts('ml_engine.js');
  console.log("🧠 Janis On-Device ML Engine Loaded Successfully");
} catch (e) {
  console.warn("⚠️ Failed to import ml_engine.js:", e);
}

let API_BASE = "http://localhost:5000";

// Load API base from extension storage if user set it in settings; otherwise use default
if (chrome && chrome.storage && chrome.storage.sync) {
  chrome.storage.sync.get(['api_base'], (res) => {
    if (res && res.api_base) {
      API_BASE = res.api_base;
      console.log("🚀 Janis AI Background Service Worker Initialized (api_base from storage):", API_BASE);
    } else {
      console.log("🚀 Janis AI Background Service Worker Initialized (default api_base):", API_BASE);
    }
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'sync' && changes.api_base) {
      API_BASE = changes.api_base.newValue || API_BASE;
      console.log('🔄 Janis AI api_base updated from storage:', API_BASE);
    }
  });
} else {
  console.log("🚀 Janis AI Background Service Worker Initialized (no storage available):", API_BASE);
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log(`📩 Incoming Message: ${request.action}`, request);

  if (request.action === "predictML") {
    if (self.janisML) {
      const result = self.janisML.predict(request.url, request.title || '', request.text || '', request.domMeta || {});
      sendResponse(result);
    } else {
      sendResponse({ error: "ML Engine Not Initialized" });
    }
    return true;
  }

  if (request.action === "scanUrl") {
    // Run On-Device ML prediction locally first (0ms latency)
    const localMLResult = self.janisML ? self.janisML.predict(request.url, request.title || '', request.text || '', request.domMeta || {}) : null;

    // allow popup to override api base for quick tests via _api_base_override
    if (request._api_base_override) {
      const original = API_BASE;
      API_BASE = request._api_base_override;
      scanUrl(request.url)
        .then(res => {
          API_BASE = original;
          res.local_ml = localMLResult;
          console.log("✅ Scan URL Result:", res);
          sendResponse(res);
        })
        .catch(err => {
          API_BASE = original;
          console.error("❌ Scan URL Error:", err);
          sendResponse({
            error: "การเชื่อมต่อล้มเหลว",
            details: err.message,
            local_ml: localMLResult,
            status: (localMLResult && localMLResult.riskScore > 65) ? "danger" : "safe"
          });
        });
      return true;
    }

    scanUrl(request.url)
      .then(res => {
        res.local_ml = localMLResult;
        console.log("✅ Scan URL Result:", res);
        sendResponse(res);
      })
      .catch(err => {
        console.error("❌ Scan URL Error:", err);
        // If server connection fails, fallback to local ML decision!
        sendResponse({
          error: "การเชื่อมต่อล้มเหลว (ใช้ระบบ ML ในเครื่องเป็นสายรอง)",
          details: err.message,
          local_ml: localMLResult,
          status: (localMLResult && localMLResult.riskScore > 65) ? "danger" : "safe"
        });
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
    const result = await postWithFallback('/scan', { url: url });
    return result;
  } catch (error) {
    console.error("⚠ Janis AI API Error (scan):", error);
    return { error: "การเชื่อมต่อล้มเหลว", details: error.message };
  }
}

async function analyzeText(text) {
  console.log(`📝 Analyzing Text (${text.length} chars)`);
  try {
    const result = await postWithFallback('/chat', {
      message: `วิเคราะห์ข้อความนี้อย่างละเอียดว่าเป็น Phishing หรืออันตรายหรือไม่: ${text.substring(0, 1500)}`
    });
    return result;
  } catch (error) {
    console.error("⚠ Janis AI API Error (chat):", error);
    return { error: "การเชื่อมต่อล้มเหลว", details: error.message };
  }
}

async function postWithFallback(path, payload) {
  const tried = [];
  const seen = new Set();
  const candidates = [API_BASE, API_BASE.replace('localhost', '127.0.0.1'), API_BASE.replace('127.0.0.1', 'localhost')];
  let lastError = null;

  for (const base of candidates) {
    if (!base) continue;
    const normalized = base.replace(/\/$/, '');
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    const url = `${normalized}${path.startsWith('/') ? path : '/' + path}`;
    tried.push(url);
    try {
      console.log(`🔁 Janis AI POST attempt -> ${url}`);
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!resp.ok) throw new Error(`HTTP error! status: ${resp.status}`);
      const json = await resp.json();
      console.log('✅ Janis API success from:', url);
      return json;
    } catch (err) {
      lastError = err;
      console.warn('⚠ Janis API attempt failed for', url, err && err.message);
      // try next candidate
      continue;
    }
  }

  const message = `All API candidates failed. Tried: ${tried.join(', ')}. Last error: ${lastError && lastError.message}`;
  const err = new Error(message);
  console.error('❌', message);
  throw err;
}

