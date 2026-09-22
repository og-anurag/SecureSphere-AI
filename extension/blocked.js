const params = new URLSearchParams(window.location.search);

const target =
  params.get("target") || "about:blank";

const risk =
  (params.get("risk") || "unknown").toUpperCase();

const score =
  params.get("score") || "N/A";

const recommendation =
  params.get("recommendation") ||
  "This page may be unsafe.";

document.getElementById("risk").textContent =
  `${risk} RISK - ${score}/100`;

document.getElementById("message").textContent =
  recommendation;


document.getElementById("leaveButton").addEventListener(
  "click",
  async () => {
    const tab = await chrome.tabs.getCurrent();

    if (tab && tab.id !== undefined) {
      await chrome.tabs.update(tab.id, {
        url: "about:blank"
      });
    }
  }
);


document.getElementById("continueButton").addEventListener(
  "click",
  () => {
    chrome.runtime.sendMessage({
      type: "SECURESPHERE_ALLOW_ONCE",
      target: target
    });
  }
);