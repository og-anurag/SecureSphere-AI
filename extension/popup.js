const saveModeButton = document.getElementById("saveMode");
const scanButton = document.getElementById("scanButton");
const status = document.getElementById("status");

const API_URL =
  "http" + "://" + "127.0.0.1:8000" + "/agent/analyze";

const DEFAULT_MODE = "manual";


function getSelectedMode() {
  const selected = document.querySelector(
    'input[name="scanMode"]:checked'
  );

  return selected ? selected.value : DEFAULT_MODE;
}


function setSelectedMode(mode) {
  const radio = document.querySelector(
    `input[name="scanMode"][value="${mode}"]`
  );

  if (radio) {
    radio.checked = true;
  }
}


async function loadSettings() {
  const data = await chrome.storage.local.get({
    scanMode: DEFAULT_MODE
  });

  setSelectedMode(data.scanMode);

  status.textContent =
    `Current mode: ${formatMode(data.scanMode)}`;
}


function formatMode(mode) {
  if (mode === "realtime-persistent") {
    return "Real-time • Persistent";
  }

  if (mode === "realtime-temporary") {
    return "Real-time • Temporary";
  }

  return "Manual Scan";
}


saveModeButton.addEventListener("click", async () => {
  const mode = getSelectedMode();

  await chrome.storage.local.set({
    scanMode: mode
  });

  status.textContent =
    `Saved: ${formatMode(mode)}`;
});


scanButton.addEventListener("click", async () => {
  status.textContent = "Scanning current page...";

  try {
    const tabs = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    const currentTab = tabs[0];

    if (!currentTab || !currentTab.url) {
      status.textContent =
        "Could not read the current page.";

      return;
    }

    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        input: currentTab.url,
        session_id: "browser-extension-manual"
      })
    });

    if (!response.ok) {
      throw new Error(
        `Backend returned ${response.status}`
      );
    }

    const report = await response.json();

    status.textContent =
      `Risk: ${report.risk_level || "unknown"} | Score: ${report.risk_score ?? "N/A"}`;

  } catch (error) {
    status.textContent =
      "Could not connect to SecureSphere backend.";
  }
});


loadSettings();