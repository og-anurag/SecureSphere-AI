import re

# Starter blacklist - in production, back this with a DB table that grows
# as users/agents report scam handles.
KNOWN_SCAM_UPI_HANDLES: set[str] = set()

SUSPICIOUS_UPI_KEYWORDS = ["lottery", "prize", "refund", "cashback", "kbc", "winner", "bonus"]

UPI_PATTERN = re.compile(r"^[\w.\-]+@[a-zA-Z]+$")


def check_payment(upi_id: str):
    score = 0
    reasons = []

    features = {
        "valid_format": False,
        "is_known_scam": False,
        "has_suspicious_naming": False,
        "is_random_looking": False,
    }

    upi_id = upi_id.strip()

    if not UPI_PATTERN.match(upi_id):
        reasons.append("Input is not a valid UPI ID format (expected handle@bank)")
        return {
            "upi_id": upi_id,
            "risk": "Low",
            "score": 0,
            "reasons": reasons,
            "features": features,
        }

    features["valid_format"] = True
    handle = upi_id.split("@")[0].lower()

    if upi_id.lower() in KNOWN_SCAM_UPI_HANDLES:
        features["is_known_scam"] = True
        score += 60
        reasons.append(f"'{upi_id}' matches a previously reported scam UPI ID")

    kw_hits = [k for k in SUSPICIOUS_UPI_KEYWORDS if k in handle]
    if kw_hits:
        features["has_suspicious_naming"] = True
        score += 30
        reasons.append(f"UPI handle contains scam-associated terms: {', '.join(kw_hits)}")

    # Very new / randomly generated-looking handles (lots of digits) are a mild signal
    digit_ratio = sum(c.isdigit() for c in handle) / max(len(handle), 1)
    if digit_ratio > 0.5:
        features["is_random_looking"] = True
        score += 15
        reasons.append(f"UPI handle '{handle}' is mostly digits, common in throwaway scam IDs")

    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "upi_id": upi_id,
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "features": features,
    }
