// popup.js - Extension UI Logic

document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const statusIcon = document.getElementById('status-icon');
  const statusLabel = document.getElementById('status-label');
  const threatInfo = document.getElementById('threat-info');
  const threatType = document.getElementById('threat-type');
  const scanBtn = document.getElementById('scan-now');
  const apiInput = document.getElementById('api-base-input');
  const saveApiBtn = document.getElementById('save-api-base');
  const testApiBtn = document.getElementById('test-api');
  const testResult = document.getElementById('test-result');

  // Show "Analyzing" initially
  setAnalyzing();

  // Initial Scan Status: Only run on Facebook / Messenger URLs
  const isFacebookTab = tab && tab.url && (tab.url.includes('facebook.com') || tab.url.includes('messenger.com'));
  if (isFacebookTab) {
    setAnalyzing();
    chrome.runtime.sendMessage({ action: "scanUrl", url: tab.url }, (response) => {
      if (response && response.status === "danger") {
        setDanger(response.details.category);
      } else if (response && response.error) {
        setError(response.error);
      } else {
        setSafe();
      }
    });
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<i class="fa-solid fa-bolt-lightning mr-2"></i> ตรวจสอบทันที';
  } else {
    // Disable scan button on non-FB tabs
    scanBtn.disabled = true;
    scanBtn.innerText = 'เฉพาะ Facebook เท่านั้น';
    setSafe();
  }

  scanBtn.onclick = () => {
    if (scanBtn.disabled) return;
    setAnalyzing();
    scanBtn.innerText = "กำลังสแกน...";
    chrome.runtime.sendMessage({ action: "scanUrl", url: tab.url }, (response) => {
      scanBtn.innerHTML = '<i class="fa-solid fa-bolt-lightning mr-2"></i> ตรวจสอบทันที';
      if (response && response.status === "danger") {
        setDanger(response.details.category);
      } else if (response && response.error) {
        setError(response.error);
      } else {
        setSafe();
      }
    });
  };

  // Load saved API base into input
  if (chrome && chrome.storage && chrome.storage.sync) {
    chrome.storage.sync.get(['api_base'], (res) => {
      if (res && res.api_base) apiInput.value = res.api_base;
    });
  }

  if (saveApiBtn) {
    saveApiBtn.onclick = () => {
      const val = apiInput.value && apiInput.value.trim();
      if (!val) {
        testResult.style.color = '#ef4444';
        testResult.innerText = 'กรุณาใส่ URL ของ API ก่อนบันทึก';
        return;
      }
      chrome.storage.sync.set({ api_base: val }, () => {
        testResult.style.color = '#10b981';
        testResult.innerText = 'บันทึกค่าเรียบร้อยแล้ว';
      });
    };
  }

  if (testApiBtn) {
    testApiBtn.onclick = () => {
      testResult.style.color = '#94a3b8';
      testResult.innerText = 'กำลังทดสอบ...';
      const testUrl = apiInput.value && apiInput.value.trim() ? apiInput.value.trim() : 'http://127.0.0.1:5000';
      // Use background scanUrl to test /scan endpoint
      chrome.runtime.sendMessage({ action: 'scanUrl', url: 'https://facebook.com', _api_base_override: testUrl }, (response) => {
        if (chrome.runtime.lastError) {
          testResult.style.color = '#ef4444';
          testResult.innerText = `Service error: ${chrome.runtime.lastError.message}`;
          return;
        }
        if (response && response.status) {
          testResult.style.color = response.status === 'danger' ? '#ef4444' : '#10b981';
          testResult.innerText = `ผลทดสอบ: ${response.status} (${response.site_name || ''})`;
        } else if (response && response.error) {
          testResult.style.color = '#ef4444';
          testResult.innerText = `Error: ${response.error}`;
        } else {
          testResult.style.color = '#ef4444';
          testResult.innerText = 'ไม่พบการตอบกลับจากเซิร์ฟเวอร์';
        }
      });
    };
  }

  function setAnalyzing() {
    statusIcon.className = "status-icon";
    statusIcon.style.color = "#7c3aed";
    statusIcon.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i>';
    statusLabel.innerText = "กำลังวิเคราะห์...";
    statusLabel.className = "status-label";
    statusLabel.style.color = "#7c3aed";
    threatInfo.style.display = "none";
  }

  function setDanger(type) {
    statusIcon.className = "status-icon danger";
    statusIcon.style.color = "#ef4444";
    statusIcon.innerHTML = '<i class="fa-solid fa-radiation"></i>';
    statusLabel.innerText = "อันตราย";
    statusLabel.className = "status-label danger";
    statusLabel.style.color = "#ef4444";
    threatInfo.style.display = "block";
    threatType.innerText = type;
  }

  function setSafe() {
    statusIcon.className = "status-icon safe";
    statusIcon.style.color = "#10b981";
    statusIcon.innerHTML = '<i class="fa-solid fa-shield-halved"></i>';
    statusLabel.innerText = "ปลอดภัย";
    statusLabel.className = "status-label safe";
    statusLabel.style.color = "#10b981";
    threatInfo.style.display = "none";
  }

  function setError(msg) {
    statusIcon.className = "status-icon";
    statusIcon.style.color = "#94a3b8";
    statusIcon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
    statusLabel.innerText = "ไม่ได้เชื่อมต่อ";
    statusLabel.className = "status-label";
    statusLabel.style.color = "#94a3b8";
    threatInfo.style.display = "block";
    threatType.innerText = "ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้";
  }
});

