import re

from ..state import SecurityState
from ..threat_intel import check_virustotal_file_hash

from app.utils.scan_adapter import apk_hash_result_to_scan_result


DANGEROUS_PERMISSIONS = [
    "READ_SMS",
    "RECEIVE_SMS",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "REQUEST_INSTALL_PACKAGES",
    "READ_CONTACTS",
    "CALL_PHONE",
]


def apk_agent_node(state: SecurityState) -> SecurityState:
    text = state["raw_input"]
    findings = state.setdefault("findings", [])

    hash_match = re.search(
        r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{32}\b",
        text,
    )

    if hash_match:
        file_hash = hash_match.group(0)

        vt = check_virustotal_file_hash(file_hash)

        unified = apk_hash_result_to_scan_result(
            result=vt,
            target=file_hash,
        )

        for finding in unified.findings:
            findings.append(
                {
                    "agent": finding.agent,
                    "signal": finding.signal,
                    "detail": finding.detail,
                    "severity": finding.severity,
                }
            )

        state["risk_score"] = unified.risk_score
        state["risk_level"] = unified.severity
        state["apk_scan_result"] = unified.model_dump()

    else:
        findings.append(
            {
                "agent": "apk_agent",
                "signal": "no_hash_provided",
                "detail": (
                    "No file hash found in input -- for a real APK upload "
                    "flow, compute SHA256 server-side before calling this agent."
                ),
                "severity": "low",
            }
        )

        state["risk_score"] = 0
        state["risk_level"] = "low"

    perm_hits = [
        permission
        for permission in DANGEROUS_PERMISSIONS
        if permission in text
    ]

    if perm_hits:
        findings.append(
            {
                "agent": "apk_agent",
                "signal": "dangerous_permissions",
                "detail": (
                    f"Requests high-risk permissions: "
                    f"{', '.join(perm_hits)}"
                ),
                "severity": "medium",
            }
        )

    return state