const API_URL =
  "http" + "://" + "127.0.0.1:8000" + "/agent/analyze";

const lastScannedByTab = new Map();
const allowOnceByTab = new Map();

console.log("SecureSphere background worker started");


async function getScanMode() {
  const data = await chrome.storage.local.get({
    scanMode: "manual"
  });

  return data.scanMode;
}


async function scanUrl(url, tabId) {
  if (
    !url.startsWith("http://") &&
    !url.startsWith("https://")
  ) {
    return;
  }

  const mode = await getScanMode();

  if (mode === "manual") {
    console.log(
      "SecureSphere manual mode - automatic scan skipped:",
      url
    );
    return;
  }

  const allowedUrl = allowOnceByTab.get(tabId);

  if (allowedUrl === url) {
    console.log(
      "SecureSphere allowing once:",
      url
    );

    allowOnceByTab.delete(tabId);
    return;
  }

  const lastUrl = lastScannedByTab.get(tabId);

  if (lastUrl === url) {
    return;
  }

  lastScannedByTab.set(tabId, url);

  console.log(
    `SecureSphere ${mode} scanning:`,
    url
  );

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        input: url,
        session_id: "browser-background"
      })
    });

    if (!response.ok) {
      throw new Error(
        `Backend returned ${response.status}`
      );
    }

    const result = await response.json();

    console.log(
      "SecureSphere scan result:",
      result
    );

    const risk = String(
      result.risk_level || ""
    ).toLowerCase();

    if (
      risk === "high" ||
      risk === "critical"
    ) {
      const blockedUrl =
        chrome.runtime.getURL("blocked.html") +
        "?" +
        new URLSearchParams({
          target: url,
          risk: risk,
          score: String(
            result.risk_score ?? 0
          ),
          recommendation:
            result.recommendation ||
            "This page may be unsafe."
        }).toString();

      console.log(
        "SecureSphere blocking page:",
        url
      );

      await chrome.tabs.update(tabId, {
        url: blockedUrl
      });

      return;
    }

    chrome.tabs.sendMessage(
      tabId,
      {
        type: "SECURESPHERE_SCAN_RESULT",
        report: result,
        mode: mode
      }
    ).catch(() => {
      // Content script may not be available.
    });

  } catch (error) {
    console.error(
      "SecureSphere scan failed:",
      error
    );
  }
}


function handleNavigation(details) {
  if (details.frameId !== 0) {
    return;
  }

  scanUrl(
    details.url,
    details.tabId
  );
}


chrome.webNavigation.onCommitted.addListener(
  handleNavigation
);


chrome.webNavigation.onHistoryStateUpdated.addListener(
  handleNavigation
);


chrome.runtime.onMessage.addListener(
  (message, sender) => {
    if (
      message.type !==
      "SECURESPHERE_ALLOW_ONCE"
    ) {
      return;
    }

    if (
      !sender.tab ||
      sender.tab.id === undefined ||
      !message.target
    ) {
      return;
    }

    const tabId = sender.tab.id;

    allowOnceByTab.set(
      tabId,
      message.target
    );

    lastScannedByTab.delete(tabId);

    chrome.tabs.update(tabId, {
      url: message.target
    });
  }
);


chrome.tabs.onRemoved.addListener((tabId) => {
  lastScannedByTab.delete(tabId);
  allowOnceByTab.delete(tabId);
});