const scanButton = document.getElementById("scanButton");
const result = document.getElementById("result");

const API_URL =
  "http" + "://" + "localhost:8000" + "/agent/analyze";

scanButton.addEventListener("click", async () => {
  result.textContent = "Scanning current page...";

  try {
    const tabs = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    const currentTab = tabs[0];

    if (!currentTab || !currentTab.url) {
      result.textContent = "Could not read the current page.";
      return;
    }

    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        input: currentTab.url,
        session_id: "browser-extension"
      })
    });

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
    }

    const data = await response.json();
    const report = data.final_report || data;
    const findings = report.findings || [];

    let findingsHtml = "";

    if (findings.length > 0) {
      findingsHtml = `
        <br>
        <strong>Findings:</strong>
        <ul>
          ${findings
            .map(
              finding =>
                `<li>${finding.detail}</li>`
            )
            .join("")}
        </ul>
      `;
    }

    result.innerHTML = `
      <strong>Risk:</strong> ${report.risk_level ?? "unknown"}<br>
      <strong>Score:</strong> ${report.risk_score ?? "N/A"}<br>
      <strong>Recommendation:</strong>
      ${report.recommendation ?? "N/A"}
      ${findingsHtml}
    `;
  } catch (error) {
    result.textContent =
      "Could not connect to SecureSphere backend.";
  }
});