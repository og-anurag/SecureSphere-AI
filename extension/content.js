let securityIndicator = null;
let protectionOverlay = null;
let hideTimer = null;


function createSecurityIndicator() {
  if (securityIndicator) {
    return securityIndicator;
  }

  securityIndicator = document.createElement("div");

  securityIndicator.id =
    "securesphere-security-indicator";

  securityIndicator.style.position = "fixed";
  securityIndicator.style.top = "18px";
  securityIndicator.style.right = "18px";
  securityIndicator.style.zIndex = "2147483647";
  securityIndicator.style.width = "250px";
  securityIndicator.style.padding = "12px 14px";
  securityIndicator.style.background = "#111C2E";
  securityIndicator.style.color = "#E7EDF7";
  securityIndicator.style.border = "1px solid #33456B";
  securityIndicator.style.borderRadius = "10px";
  securityIndicator.style.boxShadow =
    "0 8px 30px rgba(0,0,0,0.35)";
  securityIndicator.style.fontFamily =
    "Arial, sans-serif";
  securityIndicator.style.fontSize = "13px";

  securityIndicator.innerHTML = `
    <div style="
      font-weight:700;
      font-size:14px;
      margin-bottom:6px;
    ">
      🛡 SecureSphere AI
    </div>

    <div id="securesphere-status">
      Waiting for scan...
    </div>
  `;

  document.documentElement.appendChild(
    securityIndicator
  );

  return securityIndicator;
}


function removeProtectionOverlay() {
  if (protectionOverlay) {
    protectionOverlay.remove();
    protectionOverlay = null;
  }
}


function createProtectionOverlay(report) {
  if (protectionOverlay) {
    return;
  }

  protectionOverlay = document.createElement("div");

  protectionOverlay.id =
    "securesphere-protection-overlay";

  protectionOverlay.style.position = "fixed";
  protectionOverlay.style.inset = "0";
  protectionOverlay.style.zIndex = "2147483646";
  protectionOverlay.style.background =
    "rgba(8, 12, 20, 0.96)";
  protectionOverlay.style.color = "#E7EDF7";
  protectionOverlay.style.display = "flex";
  protectionOverlay.style.alignItems = "center";
  protectionOverlay.style.justifyContent = "center";
  protectionOverlay.style.fontFamily =
    "Arial, sans-serif";

  const score = report.risk_score ?? 0;
  const risk =
    String(report.risk_level || "unknown").toUpperCase();

  protectionOverlay.innerHTML = `
    <div style="
      width:min(520px, calc(100vw - 40px));
      padding:28px;
      border:1px solid #E1594B;
      border-radius:16px;
      background:#111C2E;
      box-shadow:0 20px 60px rgba(0,0,0,0.5);
      text-align:center;
    ">
      <div style="
        font-size:34px;
        margin-bottom:12px;
      ">
        ⚠️
      </div>

      <div style="
        font-size:22px;
        font-weight:700;
        margin-bottom:10px;
      ">
        Security Warning
      </div>

      <div style="
        color:#E1594B;
        font-size:16px;
        font-weight:700;
        margin-bottom:8px;
      ">
        ${risk} RISK — ${score}/100
      </div>

      <div style="
        color:#AEBBD0;
        font-size:14px;
        line-height:1.6;
        margin-bottom:22px;
      ">
        ${report.recommendation || "This page may be unsafe."}
      </div>

      <div style="
        display:flex;
        gap:10px;
        justify-content:center;
      ">
        <button
          id="securesphere-leave-page"
          style="
            border:0;
            border-radius:8px;
            padding:11px 18px;
            cursor:pointer;
            font-weight:700;
            background:#E1594B;
            color:white;
          "
        >
          Leave Page
        </button>

        <button
          id="securesphere-continue-page"
          style="
            border:1px solid #52627D;
            border-radius:8px;
            padding:11px 18px;
            cursor:pointer;
            background:#1A2740;
            color:#E7EDF7;
          "
        >
          Continue Anyway
        </button>
      </div>
    </div>
  `;

  document.documentElement.appendChild(
    protectionOverlay
  );

  const leaveButton = document.getElementById(
    "securesphere-leave-page"
  );

  const continueButton = document.getElementById(
    "securesphere-continue-page"
  );

  leaveButton.addEventListener("click", () => {
    history.back();
  });

  continueButton.addEventListener("click", () => {
    removeProtectionOverlay();
  });
}


function updateSecurityIndicator(report, mode) {
  const indicator =
    createSecurityIndicator();

  const status =
    indicator.querySelector(
      "#securesphere-status"
    );

  const risk =
    report.risk_level || "unknown";

  const score =
    report.risk_score ?? 0;

  let riskColor = "#3FBFA6";

  if (risk === "medium") {
    riskColor = "#E8A33D";
  }

  if (
    risk === "high" ||
    risk === "critical"
  ) {
    riskColor = "#E1594B";
  }

  indicator.style.borderColor =
    riskColor;

  status.innerHTML = `
    <div style="margin-bottom:5px;">
      Risk:
      <strong style="color:${riskColor};">
        ${String(risk).toUpperCase()}
      </strong>
    </div>

    <div style="margin-bottom:5px;">
      Score: ${score}/100
    </div>

    <div style="
      color:#8FA1C0;
      font-size:12px;
      line-height:1.4;
    ">
      ${report.recommendation || "Scan completed."}
    </div>
  `;

  if (
    risk === "high" ||
    risk === "critical"
  ) {
    createProtectionOverlay(report);
  } else {
    removeProtectionOverlay();
  }

  clearTimeout(hideTimer);

  if (mode === "realtime-temporary") {
    hideTimer = setTimeout(() => {
      if (securityIndicator) {
        securityIndicator.remove();
        securityIndicator = null;
      }
    }, 7000);
  }
}


chrome.runtime.onMessage.addListener(
  (message) => {
    if (
      message.type !==
      "SECURESPHERE_SCAN_RESULT"
    ) {
      return;
    }

    updateSecurityIndicator(
      message.report,
      message.mode
    );
  }
);