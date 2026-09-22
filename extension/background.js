const API_URL =
  "http" + "://" + "127.0.0.1:8000" + "/agent/analyze";

let lastScannedUrl = "";

console.log("SecureSphere background worker started");


async function getScanMode() {
  const data = await chrome.storage.local.get({
    scanMode: "manual"
  });

  return data.scanMode;
}


async function scanUrl(url, tabId) {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return;
  }

  const mode = await getScanMode();

  if (mode === "manual") {
    console.log("SecureSphere manual mode - automatic scan skipped:", url);
    return;
  }

  if (url === lastScannedUrl) {
    return;
  }

  lastScannedUrl = url;

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

    chrome.tabs.sendMessage(
      tabId,
      {
        type: "SECURESPHERE_SCAN_RESULT",
        report: result,
        mode: mode
      }
    ).catch(() => {
      // Content script may not be available on browser-controlled pages.
    });

  } catch (error) {
    console.error(
      "SecureSphere scan failed:",
      error
    );
  }
}


chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) {
    return;
  }

  scanUrl(details.url, details.tabId);
});