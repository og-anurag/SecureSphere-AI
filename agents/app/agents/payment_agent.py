import re

from ..state import SecurityState
from app.utils.scan_adapter import payment_result_to_scan_result


KNOWN_SCAM_UPI_HANDLES: set[str] = set()

SUSPICIOUS_UPI_KEYWORDS = [
    "lottery",
    "prize",
    "refund",
    "cashback",
    "kbc",
    "winner",
]


def payment_agent_node(state: SecurityState) -> SecurityState:
    findings = state.setdefault("findings", [])

    # Use a payment result already calculated by the production scanner.
    precomputed = state.get("precomputed_scan_result")

    if precomputed:
        state["payment_scan_result"] = precomputed

        for finding in precomputed.get("findings", []):
            findings.append(finding)

        state["risk_score"] = int(
            precomputed.get("risk_score", 0)
        )
        state["risk_level"] = str(
            precomputed.get("severity", "low")
        )

        return state

    # Legacy/direct agent input path.
    text = state["raw_input"].strip()

    upi_match = re.search(
        r"[\w.\-]+@[a-zA-Z]+",
        text,
    )

    if not upi_match:
        findings.append(
            {
                "agent": "payment_agent",
                "signal": "unparseable_payment_input",
                "detail": (
                    "Could not extract a UPI ID or payment URL from input."
                ),
                "severity": "low",
            }
        )
        state["risk_score"] = 0
        state["risk_level"] = "low"
        return state

    upi_id = upi_match.group(0)
    handle = upi_id.split("@")[0].lower()

    if upi_id.lower() in KNOWN_SCAM_UPI_HANDLES:
        findings.append(
            {
                "agent": "payment_agent",
                "signal": "known_scam_upi",
                "detail": (
                    f"'{upi_id}' matches a previously reported scam UPI ID."
                ),
                "severity": "high",
            }
        )

    kw_hits = [
        keyword
        for keyword in SUSPICIOUS_UPI_KEYWORDS
        if keyword in handle
    ]

    if kw_hits:
        findings.append(
            {
                "agent": "payment_agent",
                "signal": "suspicious_upi_naming",
                "detail": (
                    "UPI handle contains scam-associated terms: "
                    + ", ".join(kw_hits)
                ),
                "severity": "high",
            }
        )

    digit_ratio = sum(
        character.isdigit()
        for character in handle
    ) / max(len(handle), 1)

    if digit_ratio > 0.5:
        findings.append(
            {
                "agent": "payment_agent",
                "signal": "random_looking_handle",
                "detail": (
                    f"UPI handle '{handle}' is mostly digits, "
                    "common in throwaway scam IDs."
                ),
                "severity": "low",
            }
        )

    return state