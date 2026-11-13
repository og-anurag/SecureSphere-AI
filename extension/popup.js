const saveModeButton =
  document.getElementById("saveMode");

const scanButton =
  document.getElementById("scanButton");

const status =
  document.getElementById("status");
const privacyNotice =
  document.getElementById("privacyNotice");

const privacyNoticeToggle =
  document.getElementById("privacyNoticeToggle");

const privacyNoticeContent =
  document.getElementById("privacyNoticeContent");

const privacyNoticeChevron =
  document.getElementById("privacyNoticeChevron");

function setPrivacyNoticeExpanded(expanded) {
  privacyNoticeContent.hidden = !expanded;

  privacyNoticeToggle.setAttribute(
    "aria-expanded",
    String(expanded)
  );

  privacyNoticeChevron.textContent =
    expanded ? "−" : "+";
}

privacyNoticeToggle.addEventListener("click", () => {
  setPrivacyNoticeExpanded(privacyNoticeContent.hidden);
});

document.addEventListener("click", (event) => {
  if (!privacyNotice.contains(event.target)) {
    setPrivacyNoticeExpanded(false);
  }
});

const privacyConsent =
  document.getElementById("privacyConsent");
const privacyConsentLabel =
  document.getElementById("privacyConsentLabel");

const changeConsentButton =
  document.getElementById("changeConsent");

const latestScan =
  document.getElementById("latestScan");

const latestUrl =
  document.getElementById("latestUrl");

const latestRisk =
  document.getElementById("latestRisk");

const latestScore =
  document.getElementById("latestScore");

const reportPanel =
  document.getElementById("report");
const scanProgress =
  document.getElementById("scanProgress");

const resultModal =
  document.getElementById("resultModal");

const modalReportHost =
  document.getElementById("modalReportHost");

const closeResultModalButton =
  document.getElementById("closeResultModal");

const riskLevel =
  document.getElementById("riskLevel");

const riskScore =
  document.getElementById("riskScore");

const confidence =
  document.getElementById("confidence");

const recommendation =
  document.getElementById("recommendation");

const findings =
  document.getElementById("findings");


const API_URL =
  "https://securesphere-ai-api.onrender.com/agent/analyze";

const DEFAULT_MODE = "manual";


function getSelectedMode() {
  const selected =
    document.querySelector(
      'input[name="scanMode"]:checked'
    );

  return selected
    ? selected.value
    : DEFAULT_MODE;
}


function setSelectedMode(mode) {
  const radio =
    document.querySelector(
      `input[name="scanMode"][value="${mode}"]`
    );

  if (radio) {
    radio.checked = true;
  }
}
async function updateModeHighlight() {
  const data = await chrome.storage.local.get({
    scanMode: DEFAULT_MODE
  });

  const activeMode = data.scanMode || DEFAULT_MODE;

  document.querySelectorAll(".mode").forEach((label) => {
    const radio = label.querySelector('input[name="scanMode"]');

    label.classList.toggle(
      "active-mode",
      Boolean(radio && radio.value === activeMode)
    );
  });
}

function syncConsentUI() {
  const consentGiven = privacyConsent.checked === true;

  privacyConsentLabel.style.display =
    consentGiven ? "none" : "flex";

  changeConsentButton.style.display =
    consentGiven ? "inline-block" : "none";
}

document.querySelectorAll('input[name="scanMode"]').forEach((radio) => {
  radio.addEventListener("change", () => {
    updateModeHighlight();
    saveModeButton.classList.remove("saved");
    saveModeButton.textContent = "Save Protection Mode";
  });
});

function formatMode(mode) {
  if (mode === "realtime-persistent") {
    return "Real-time • Persistent";
  }

  if (mode === "realtime-temporary") {
    return "Real-time • Temporary";
  }

  return "Manual Scan";
}


async function loadSettings() {
  const data =
    await chrome.storage.local.get({
      scanMode: DEFAULT_MODE,
      privacyConsent: false
    });

  privacyConsent.checked = data.privacyConsent === true;

  let mode = data.scanMode || DEFAULT_MODE;
  const isRealtime =
    mode === "realtime-persistent" ||
    mode === "realtime-temporary";

  if (isRealtime && !privacyConsent.checked) {
    mode = DEFAULT_MODE;
    await chrome.storage.local.set({
      scanMode: DEFAULT_MODE
    });
  }

  setSelectedMode(mode);
syncConsentUI();
updateModeHighlight();

status.textContent =
  `Current mode: ${formatMode(mode)}`;
}


function riskColor(risk) {
  const normalized =
    String(risk || "").toLowerCase();

  if (
    normalized === "critical" ||
    normalized === "high"
  ) {
    return "#dc2626";
  }

  if (normalized === "medium") {
    return "#d97706";
  }

  if (normalized === "low") {
    return "#059669";
  }

  return "#6b7280";
}


function renderFindings(items) {
  findings.innerHTML = "";

  if (
    !Array.isArray(items) ||
    items.length === 0
  ) {
    const item =
      document.createElement("li");

    item.textContent =
      "No detailed findings returned.";

    findings.appendChild(item);
    return;
  }

  items.slice(0, 6).forEach((finding) => {
    const item =
      document.createElement("li");

    const signal =
      finding.signal || "Finding";

    const detail =
      finding.detail ||
      "No detail available.";

    item.textContent =
      `${signal}: ${detail}`;

    findings.appendChild(item);
  });
}


function renderReport(report) {
  const risk = report.risk_level || "unknown";
  const score = report.risk_score ?? "N/A";
  const confidenceValue = report.confidence;

  riskLevel.textContent = String(risk).toUpperCase();
  riskLevel.style.color = riskColor(risk);

  riskScore.textContent = `${score}/100`;

  confidence.textContent =
    confidenceValue === undefined
      ? "N/A"
      : `${Math.round(Number(confidenceValue) * 100)}%`;

  recommendation.textContent =
    report.recommendation ||
    "No recommendation returned.";

  renderFindings(report.findings);

  // Move the existing report into the result modal.
  modalReportHost.appendChild(reportPanel);
  reportPanel.style.display = "block";
  resultModal.hidden = false;
}
closeResultModalButton.addEventListener("click", () => {
  resultModal.hidden = true;
});

resultModal.addEventListener("click", (event) => {
  if (event.target === resultModal) {
    resultModal.hidden = true;
  }
});

async function loadLatestAutomaticScan() {
  const data =
    await chrome.storage.local.get(
      "lastAutomaticScan"
    );

  if (!data.lastAutomaticScan) {
    return;
  }

  const scan =
    data.lastAutomaticScan;

  const report =
    scan.report || {};

  latestUrl.textContent =
    scan.url || "Unknown URL";

  latestRisk.textContent =
    String(
      report.risk_level || "unknown"
    ).toUpperCase();

  latestRisk.style.color =
    riskColor(report.risk_level);

  latestScore.textContent =
    `${report.risk_score ?? "N/A"}/100`;

  latestScan.style.display = "block";

  // When opened by Real-time Temporary, show the full report modal.
  if (scan.mode === "realtime-temporary") {
    renderReport(report);
  }
}


saveModeButton.addEventListener("click", async () => {
  const mode = getSelectedMode();
  const isRealtime =
    mode === "realtime-persistent" ||
    mode === "realtime-temporary";

  saveModeButton.classList.remove("saved");
  saveModeButton.textContent = "Save Protection Mode";

  if (isRealtime && !privacyConsent.checked) {
    setSelectedMode(DEFAULT_MODE);

    await chrome.storage.local.set({
      scanMode: DEFAULT_MODE
    });

    await updateModeHighlight();

    status.textContent =
      "Check the privacy consent box before enabling real-time scanning. Manual Scan remains enabled.";
    return;
  }

  await chrome.storage.local.set({
    scanMode: mode,
    privacyConsent: privacyConsent.checked
  });

  await updateModeHighlight();

  saveModeButton.classList.add("saved");
  saveModeButton.textContent = "Saved ✓";
  status.textContent = `Saved: ${formatMode(mode)}`;
});

privacyConsent.addEventListener("change", async () => {
  const consentGiven = privacyConsent.checked === true;

  await chrome.storage.local.set({
    privacyConsent: consentGiven
  });

  syncConsentUI();

  if (!consentGiven) {
    setSelectedMode(DEFAULT_MODE);

    await chrome.storage.local.set({
      scanMode: DEFAULT_MODE
    });

    status.textContent =
      "Consent removed. Manual Scan is enabled.";
  } else {
    status.textContent =
      "URL-sharing consent saved. Select a mode and click Save Protection Mode.";
  }

  updateModeHighlight();
});

changeConsentButton.addEventListener("click", async () => {
  privacyConsent.checked = false;

  await chrome.storage.local.set({
    privacyConsent: false,
    scanMode: DEFAULT_MODE
  });

  setSelectedMode(DEFAULT_MODE);
  syncConsentUI();
  updateModeHighlight();

  status.textContent =
    "Consent removed. Manual Scan is enabled.";
});


scanButton.addEventListener("click", async () => {
  status.textContent = "Scanning current page...";
  reportPanel.style.display = "none";
  resultModal.hidden = true;
  scanProgress.hidden = false;

  scanButton.disabled = true;
  scanButton.textContent = "Scanning...";

  try {
    const tabs = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    const currentTab = tabs[0];

    if (!currentTab || !currentTab.url) {
      status.textContent = "Could not read the current page.";
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
      throw new Error(`Backend returned ${response.status}`);
    }

    const report = await response.json();

    renderReport(report);

    status.textContent =
      `Scan complete: ${String(report.risk_level || "unknown").toUpperCase()}`;
  } catch (error) {
    console.error("SecureSphere manual scan failed:", error);
    status.textContent = "Could not connect to SecureSphere backend.";
  } finally {
    scanProgress.hidden = true;
    scanButton.disabled = false;
    scanButton.textContent = "Scan Current Page";
  }
});

loadSettings();
loadLatestAutomaticScan();
