let securityPopup = null;

function showSecurityPopup(report) {
  if (securityPopup) {
    securityPopup.remove();
  }

  const risk = report.risk_level || "unknown";
  const score = report.risk_score ?? 0;

  let riskColor = "#3FBFA6";

  if (risk === "medium") {
    riskColor = "#E8A33D";
  } else if (risk === "high" || risk === "critical") {
    riskColor = "#E1594B";
  }

  securityPopup = document.createElement("div");

  securityPopup.style.position = "fixed";
  securityPopup.style.top = "20px";
  securityPopup.style.right = "20px";
  securityPopup.style.zIndex = "2147483647";
  securityPopup.style.width = "280px";
  securityPopup.style.padding = "14px";
  securityPopup.style.background = "#111C2E";
  securityPopup.style.color = "#E7EDF7";
  securityPopup.style.border = `1px solid ${riskColor}`;
  securityPopup.style.borderRadius = "10px";
  securityPopup.style.boxShadow = "0 8px 30px rgba(0,0,0,0.35)";
  securityPopup.style.fontFamily = "Arial, sans-serif";

  securityPopup.innerHTML = `
    <div style="font-weight:700;font-size:15px;margin-bottom:8px;">
      🛡 SecureSphere AI
    </div>

    <div style="font-size:13px;margin-bottom:6px;">
      Risk:
      <strong style="color:${riskColor};">
        ${risk.toUpperCase()}
      </strong>
    </div>

    <div style="font-size:13px;margin-bottom:10px;">
      Score: ${score}/100
    </div>

    <div style="font-size:12px;color:#8FA1C0;">
      ${report.recommendation || "Scan completed."}
    </div>
  `;

  document.documentElement.appendChild(securityPopup);

  setTimeout(() => {
    if (securityPopup) {
      securityPopup.remove();
      securityPopup = null;
    }
  }, 7000);
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type !== "SECURESPHERE_SCAN_RESULT") {
    return;
  }

  showSecurityPopup(message.report);
});