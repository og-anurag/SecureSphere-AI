from ..state import SecurityState
from app.utils.scan_adapter import qr_result_to_scan_result


def qr_agent_node(state: SecurityState) -> SecurityState:
    findings = state.setdefault("findings", [])

    precomputed = state.get("precomputed_scan_result")

    if precomputed:
        state["qr_scan_result"] = precomputed

        for finding in precomputed.get("findings", []):
            findings.append(finding)

        state["risk_score"] = int(precomputed.get("risk_score", 0))
        state["risk_level"] = str(precomputed.get("severity", "low"))

        return state

    findings.append({
        "agent": "qr_agent",
        "signal": "no_scan_result",
        "detail": "No precomputed QR scan result was provided.",
        "severity": "low",
    })

    state["risk_score"] = 0
    state["risk_level"] = "low"

    return state