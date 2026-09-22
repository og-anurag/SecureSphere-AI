let securityIndicator = null;
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