import re
from app.state import SecurityState

# Starter blacklist — in a real build, back this with a shared DB table
# that grows as users/agents report scam handles.
KNOWN_SCAM_UPI_HANDLES: set[str] = set()

SUSPICIOUS_UPI_KEYWORDS = ["lottery", "prize", "refund", "cashback", "kbc", "winner"]


def payment_agent_node(state: SecurityState) -> SecurityState:
    text = state["raw_input"].strip()
    findings = state.setdefault("findings", [])

    upi_match = re.search(r"[\w.\-]+@[a-zA-Z]+", text)
    if not upi_match:
        findings.append({
            "agent": "payment_agent",
            "signal": "unparseable_payment_input",
            "detail": "Could not extract a UPI ID or payment URL from input.",
            "severity": "low",
        })
        return state

    upi_id = upi_match.group(0)
    handle = upi_id.split("@")[0].lower()

    if upi_id.lower() in KNOWN_SCAM_UPI_HANDLES:
        findings.append({
            "agent": "payment_agent",
            "signal": "known_scam_upi",
            "detail": f"'{upi_id}' matches a previously reported scam UPI ID.",
            "severity": "high",
        })

    kw_hits = [k for k in SUSPICIOUS_UPI_KEYWORDS if k in handle]
    if kw_hits:
        findings.append({
            "agent": "payment_agent",
            "signal": "suspicious_upi_naming",
            "detail": f"UPI handle contains scam-associated terms: {', '.join(kw_hits)}",
            "severity": "high",
        })

    # Very new / randomly generated-looking handles (lots of digits) are a mild signal
    digit_ratio = sum(c.isdigit() for c in handle) / max(len(handle), 1)
    if digit_ratio > 0.5:
        findings.append({
            "agent": "payment_agent",
            "signal": "random_looking_handle",
            "detail": f"UPI handle '{handle}' is mostly digits, common in throwaway scam IDs.",
            "severity": "low",
        })

    return state
