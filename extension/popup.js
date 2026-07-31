// popup.js - Extension UI Logic

document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const statusIcon = document.getElementById('status-icon');
  const statusLabel = document.getElementById('status-label');
  const threatInfo = document.getElementById('threat-info');
  const threatType = document.getElementById('threat-type');
  const scanBtn = document.getElementById('scan-now');

  // Show "Analyzing" initially
  setAnalyzing();

  // Initial Scan Status from Current URL
  if (tab && tab.url && !tab.url.startsWith("chrome://")) {
    chrome.runtime.sendMessage({ action: "scanUrl", url: tab.url }, (response) => {
      if (response && response.status === "danger") {
        setDanger(response.details.category);
      } else if (response && response.error) {
          setError(response.error);
      } else {
        setSafe();
      }
    });
  } else {
      setSafe();
  }

  scanBtn.onclick = () => {
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
