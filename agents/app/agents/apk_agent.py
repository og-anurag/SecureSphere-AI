import re
from app.state import SecurityState
from app.threat_intel import check_virustotal_file_hash

# Permissions that are disproportionately common in banking-trojan / spyware APKs.
DANGEROUS_PERMISSIONS = [
    "READ_SMS", "RECEIVE_SMS", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
    "REQUEST_INSTALL_PACKAGES", "READ_CONTACTS", "CALL_PHONE",
]


def apk_agent_node(state: SecurityState) -> SecurityState:
    text = state["raw_input"]
    findings = state.setdefault("findings", [])

    # 1. If a hash was supplied, check it against VirusTotal
    hash_match = re.search(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{32}\b", text)
    if hash_match:
        vt = check_virustotal_file_hash(hash_match.group(0))
        if vt.get("flagged"):
            findings.append({
                "agent": "apk_agent",
                "signal": "virustotal_flagged",
                "detail": f"VirusTotal flagged this file: {vt.get('stats')}",
                "severity": "high",
            })
        elif not vt.get("checked"):
            findings.append({
                "agent": "apk_agent",
                "signal": "vt_check_unavailable",
                "detail": "Could not verify against VirusTotal (missing key or API error).",
                "severity": "low",
            })
    else:
        findings.append({
            "agent": "apk_agent",
            "signal": "no_hash_provided",
            "detail": "No file hash found in input — for a real APK upload flow, "
                      "compute SHA256 server-side before calling this agent.",
            "severity": "low",
        })

    # 2. Dangerous permission mentions (useful once you parse AndroidManifest.xml for real)
    perm_hits = [p for p in DANGEROUS_PERMISSIONS if p in text]
    if perm_hits:
        findings.append({
            "agent": "apk_agent",
            "signal": "dangerous_permissions",
            "detail": f"Requests high-risk permissions: {', '.join(perm_hits)}",
            "severity": "medium",
        })

    return state
