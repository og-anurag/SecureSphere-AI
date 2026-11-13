
let securityIndicator = null;
let protectionOverlay = null;
let hideTimer = null;

function createElement(tag, styles = {}, text = null) {
  const element = document.createElement(tag);

  Object.assign(element.style, styles);

  if (text !== null) {
    element.textContent = String(text);
  }

  return element;
}

function createSecurityIndicator() {
  if (securityIndicator) {
    return securityIndicator;
  }

  securityIndicator = createElement("div", {
    position: "fixed",
    top: "18px",
    right: "18px",
    zIndex: "2147483647",
    width: "250px",
    padding: "12px 14px",
    background: "#111C2E",
    color: "#E7EDF7",
    border: "1px solid #33456B",
    borderRadius: "10px",
    boxShadow: "0 8px 30px rgba(0,0,0,0.35)",
    fontFamily: "Arial, sans-serif",
    fontSize: "13px"
  });

  securityIndicator.id = "securesphere-security-indicator";

  const heading = createElement("div", {
    fontWeight: "700",
    fontSize: "14px",
    marginBottom: "6px"
  }, "🛡 SecureSphere AI");

  const status = createElement("div", {}, "Waiting for scan...");
  status.id = "securesphere-status";

  securityIndicator.append(heading, status);

  document.documentElement.appendChild(securityIndicator);

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

  protectionOverlay = createElement("div", {
    position: "fixed",
    inset: "0",
    zIndex: "2147483646",
    background: "rgba(8, 12, 20, 0.96)",
    color: "#E7EDF7",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontFamily: "Arial, sans-serif"
  });

  protectionOverlay.id = "securesphere-protection-overlay";

  const card = createElement("div", {
    width: "min(520px, calc(100vw - 40px))",
    padding: "28px",
    border: "1px solid #E1594B",
    borderRadius: "16px",
    background: "#111C2E",
    boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
    textAlign: "center"
  });

  const warningIcon = createElement("div", {
    fontSize: "34px",
    marginBottom: "12px"
  }, "⚠️");

  const heading = createElement("div", {
    fontSize: "22px",
    fontWeight: "700",
    marginBottom: "10px"
  }, "Security Warning");

  const score = Number(report.risk_score);
  const safeScore = Number.isFinite(score) ? score : 0;

  const risk = String(report.risk_level || "unknown")
    .toUpperCase()
    .slice(0, 30);

  const riskText = createElement("div", {
    color: "#E1594B",
    fontSize: "16px",
    fontWeight: "700",
    marginBottom: "8px"
  }, `${risk} RISK — ${safeScore}/100`);

  const recommendation = createElement("div", {
    color: "#AEBBD0",
    fontSize: "14px",
    lineHeight: "1.6",
    marginBottom: "22px"
  }, report.recommendation || "This page may be unsafe.");

  const buttonContainer = createElement("div", {
    display: "flex",
    gap: "10px",
    justifyContent: "center"
  });

  const leaveButton = createElement("button", {
    border: "0",
    borderRadius: "8px",
    padding: "11px 18px",
    cursor: "pointer",
    fontWeight: "700",
    background: "#E1594B",
    color: "white"
  }, "Leave Page");

  leaveButton.id = "securesphere-leave-page";

  const continueButton = createElement("button", {
    border: "1px solid #52627D",
    borderRadius: "8px",
    padding: "11px 18px",
    cursor: "pointer",
    background: "#1A2740",
    color: "#E7EDF7"
  }, "Continue Anyway");

  continueButton.id = "securesphere-continue-page";

  buttonContainer.append(leaveButton, continueButton);

  card.append(
    warningIcon,
    heading,
    riskText,
    recommendation,
    buttonContainer
  );

  protectionOverlay.appendChild(card);
  document.documentElement.appendChild(protectionOverlay);

  leaveButton.addEventListener("click", () => {
    history.back();
  });

  continueButton.addEventListener("click", () => {
    removeProtectionOverlay();
  });
}

function updateSecurityIndicator(report, mode) {
  const indicator = createSecurityIndicator();

  const status = indicator.querySelector("#securesphere-status");

  const risk = String(report.risk_level || "unknown");
  const score = Number(report.risk_score);
  const safeScore = Number.isFinite(score) ? score : 0;

  let riskColor = "#3FBFA6";

  if (risk.toLowerCase() === "medium") {
    riskColor = "#E8A33D";
  }

  if (
    risk.toLowerCase() === "high" ||
    risk.toLowerCase() === "critical"
  ) {
    riskColor = "#E1594B";
  }

  indicator.style.borderColor = riskColor;

  const riskLine = createElement("div", {
    marginBottom: "5px"
  }, "Risk: ");

  const riskValue = createElement("strong", {
    color: riskColor
  }, risk.toUpperCase());

  riskLine.appendChild(riskValue);

  const scoreLine = createElement("div", {
    marginBottom: "5px"
  }, `Score: ${safeScore}/100`);

  const recommendation = createElement("div", {
    color: "#8FA1C0",
    fontSize: "12px",
    lineHeight: "1.4"
  }, report.recommendation || "Scan completed.");

  status.replaceChildren(
    riskLine,
    scoreLine,
    recommendation
  );

  if (
    risk.toLowerCase() === "high" ||
    risk.toLowerCase() === "critical"
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

chrome.runtime.onMessage.addListener((message) => {
  if (
    !message ||
    message.type !== "SECURESPHERE_SCAN_RESULT"
  ) {
    return;
  }

  updateSecurityIndicator(
    message.report || {},
    message.mode
  );
});
