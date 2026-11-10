$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot
$sourceExtension = Join-Path $repoRoot 'extension'
$manifestPath = Join-Path $sourceExtension 'manifest.json'

if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Could not find extension\manifest.json. Save this script in the SecureSphere-AI project root and run it there."
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.manifest_version -ne 3) {
    throw 'The extension manifest is not Manifest V3; stopping without building the tester ZIP.'
}

$requiredFiles = @(
    'background.js', 'content.js', 'manifest.json', 'popup.html', 'popup.js', 'blocked.html', 'blocked.js',
    'icons\icon16.png', 'icons\icon32.png', 'icons\icon48.png', 'icons\icon128.png'
)
foreach ($relativePath in $requiredFiles) {
    $candidate = Join-Path $sourceExtension $relativePath
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Required extension file is missing: $relativePath"
    }
}

$apiUrl = 'https://securesphere-ai-api.onrender.com'
if ($manifest.host_permissions -notcontains "$apiUrl/*") {
    throw 'The manifest does not list the deployed SecureSphere API host permission. Check extension\manifest.json first.'
}

$packageName = 'SecureSphereAI-Chrome-Tester'
$stageRoot = Join-Path $env:TEMP $packageName
$stagedExtension = Join-Path $stageRoot 'extension'
$outputZip = Join-Path $repoRoot "$packageName.zip"

if (Test-Path -LiteralPath $stageRoot) {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $stagedExtension -Force | Out-Null
Copy-Item -Path (Join-Path $sourceExtension '*') -Destination $stagedExtension -Recurse -Force

# Reduce permissions for the tester package: the extension uses the hosted API,
# so the old local-development API permission is not needed in this ZIP.
$stagedManifestPath = Join-Path $stagedExtension 'manifest.json'
$stagedManifest = Get-Content -LiteralPath $stagedManifestPath -Raw | ConvertFrom-Json
$stagedManifest.host_permissions = @(
    $stagedManifest.host_permissions | Where-Object { $_ -ne 'http://127.0.0.1:8000/*' }
)
$stagedManifest | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $stagedManifestPath -Encoding UTF8

$licensePath = Join-Path $repoRoot 'LICENSE'
if (Test-Path -LiteralPath $licensePath -PathType Leaf) {
    Copy-Item -LiteralPath $licensePath -Destination (Join-Path $stageRoot 'LICENSE') -Force
}

$readme = @'
SecureSphere AI - Chrome Extension Tester Pack
==============================================

STATUS
------
This is an early tester build for manual installation in Google Chrome. It is
not a Chrome Web Store release and has not completed full production security
review.

INSTALL (Chrome on desktop)
---------------------------
1. Extract this ZIP to a normal folder.
2. Open chrome://extensions in Chrome.
3. Turn on Developer mode.
4. Click Load unpacked.
5. Select the extracted "extension" folder (the folder containing manifest.json).
6. Open https://example.com and click the SecureSphere AI toolbar icon.
7. Keep Manual Scan selected and click Scan Current Page to run a test.

PRIVACY AND CONSENT
-------------------
- Manual Scan is the default. It sends the current page URL to the hosted
  SecureSphere AI API only when the user presses Scan Current Page.
- Real-time modes send page URLs to the hosted API as navigation occurs.
  A consent checkbox in the extension must be checked to enable these modes.
  Removing consent returns the extension to Manual Scan.
- The extension requests access to all URLs so it can inspect the current page
  URL and, if enabled by the user, scan navigation. Consider these permissions
  carefully before installing.
- URLs can include sensitive query parameters or identifiers. Do not scan pages
  with private account links, session tokens, confidential records, or other
  sensitive URL data during testing.
- Scans are sent to: https://securesphere-ai-api.onrender.com
  Do not assume that requests or scan records are never logged or retained.
  Review the service's privacy and retention behavior before wider distribution.
- Never put passwords, API keys, database URLs, or authentication tokens in this
  package, screenshots, bug reports, or chat messages.

TEST NOTES
----------
- The hosted API is on a free Render plan and may take time to wake after idle.
- Security scores are heuristic outputs, not guarantees that a page or file is
  safe. A Low score must not be treated as proof of safety.
- Google Safe Browsing was not configured during the latest smoke test, so that
  integration was skipped.
- The warning-page buttons were tested using simulated warning parameters; an
  actual high-risk scan triggering the warning has not yet been verified.
- For bugs, report the browser version, the action taken, the HTTP status or
  error text, and steps to reproduce. Remove URL query secrets and all personal
  data before sending logs.

UNINSTALL
---------
Open chrome://extensions and click Remove on SecureSphere AI.

END
'@
Set-Content -LiteralPath (Join-Path $stageRoot 'README-TESTERS.txt') -Value $readme -Encoding UTF8

if (Test-Path -LiteralPath $outputZip) {
    Remove-Item -LiteralPath $outputZip -Force
}
Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $outputZip -CompressionLevel Optimal

Write-Host ''
Write-Host 'Tester pack created:' -ForegroundColor Green
Write-Host $outputZip
Write-Host 'Included: extension folder, README-TESTERS.txt, and LICENSE if present. The tester manifest omits the obsolete localhost API permission. Backend secrets and the smoke-test script are not included.'
