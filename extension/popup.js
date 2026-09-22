const saveModeButton =
  document.getElementById("saveMode");

const scanButton =
  document.getElementById("scanButton");

const status =
  document.getElementById("status");

const reportPanel =
  document.getElementById("report");

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
  "http" + "://" + "127.0.0.1:8000" + "/agent/analyze";

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
      scanMode: DEFAULT_MODE
    });

  setSelectedMode(data.scanMode);

  status.textContent =
    `Current mode: ${formatMode(data.scanMode)}`;
}


function riskColor(risk) {
  const normalized =
    String(risk || "").toLowerCase();

  if (normalized === "critical" ||
      normalized === "high") {
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

  if (!Array.isArray(items) || items.length === 0) {
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
      finding.detail || "No detail available.";

    item.textContent =
      `${signal}: ${detail}`;

    findings.appendChild(item);
  });
}


function renderReport(report) {
  const risk =
    report.risk_level || "unknown";

  const score =
    report.risk_score ?? "N/A";

  const confidenceValue =
    report.confidence;

  riskLevel.textContent =
    String(risk).toUpperCase();

  riskLevel.style.color =
    riskColor(risk);

  riskScore.textContent =
    `${score}/100`;

  confidence.textContent =
    confidenceValue === undefined
      ? "N/A"
      : `${Math.round(
          Number(confidenceValue) * 100
        )}%`;

  recommendation.textContent =
    report.recommendation ||
    "No recommendation returned.";

  renderFindings(
    report.findings
  );

  reportPanel.style.display =
    "block";
}


saveModeButton.addEventListener(
  "click",
  async () => {
    const mode =
      getSelectedMode();

    await chrome.storage.local.set({
      scanMode: mode
    });

    status.textContent =
      `Saved: ${formatMode(mode)}`;
  }
);


scanButton.addEventListener(
  "click",
  async () => {
    status.textContent =
      "Scanning current page...";

    reportPanel.style.display =
      "none";

    try {
      const tabs =
        await chrome.tabs.query({
          active: true,
          currentWindow: true
        });

      const currentTab =
        tabs[0];

      if (
        !currentTab ||
        !currentTab.url
      ) {
        status.textContent =
          "Could not read the current page.";

        return;
      }

      const response =
        await fetch(API_URL, {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json"
          },
          body: JSON.stringify({
            input: currentTab.url,
            session_id:
              "browser-extension-manual"
          })
        });

      if (!response.ok) {
        throw new Error(
          `Backend returned ${response.status}`
        );
      }

      const report =
        await response.json();

      renderReport(report);

      status.textContent =
        `Scan complete: ${
          String(
            report.risk_level || "unknown"
          ).toUpperCase()
        }`;

    } catch (error) {
      console.error(
        "SecureSphere manual scan failed:",
        error
      );

      status.textContent =
        "Could not connect to SecureSphere backend.";
    }
  }
);


loadSettings();