import re
from app.utils.url_checker import check_url


SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "verification",
    "account",
    "password",
    "login",
    "suspended",
    "confirm",
    "security",
    "click",
]

URGENCY_PHRASES = [
    "act now", "urgent", "verify your account", "suspended", "click here immediately",
    "limited time", "your account will be closed", "confirm your identity", "final notice",
]

CREDENTIAL_REQUEST_PHRASES = [
    "enter your password", "confirm your ssn", "otp", "one time password", "cvv", "pin number",
]


def _sender_replyto_mismatch(sender: str, body: str):
    """Detects a From/Reply-To domain mismatch, a classic spoofing tell."""
    from_domain = sender.split("@")[-1].lower() if "@" in sender else None

    reply_match = re.search(r"reply-to:\s*.*<?([\w.\-]+@[\w.\-]+)>?", body, re.IGNORECASE)
    if from_domain and reply_match:
        reply_domain = reply_match.group(1).split("@")[-1].lower()
        if reply_domain != from_domain:
            return reply_domain
    return None


def check_email(sender: str, subject: str, body: str):
    score = 0
    reasons = []

    has_suspicious_keywords = False
    has_links = False
    has_urgency_language = False
    has_credential_request = False
    has_sender_mismatch = False

    text = f"{subject} {body}".lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            has_suspicious_keywords = True
            score += 10
            reasons.append(f"Contains suspicious keyword: {keyword}")

    # Urgency / pressure language - classic social engineering
    urgency_hits = [p for p in URGENCY_PHRASES if p in text]
    if urgency_hits:
        has_urgency_language = True
        score += 15
        reasons.append(f"Uses pressure/urgency tactics: {', '.join(urgency_hits[:3])}")

    # Requests for credentials/OTP - no legitimate service asks this way
    cred_hits = [p for p in CREDENTIAL_REQUEST_PHRASES if p in text]
    if cred_hits:
        has_credential_request = True
        score += 25
        reasons.append(f"Requests sensitive info: {', '.join(cred_hits[:3])}")

    # Sender / Reply-To mismatch
    mismatch_domain = _sender_replyto_mismatch(sender, body)
    if mismatch_domain:
        has_sender_mismatch = True
        score += 25
        reasons.append(
            f"Reply-To domain '{mismatch_domain}' differs from sender domain - possible spoofing"
        )

    urls = re.findall(r"https?://[^\s]+", body)
    urls = [url.rstrip(".,!?;:") for url in urls]

    if urls:
        has_links = True
        score += 20
        reasons.append("Email contains a link")

        for url in urls:
            url_result = check_url(url)

            if url_result["score"] > 0:
                score += url_result["score"]
                reasons.append(
                    f"Link risk: {url_result['risk']} - {url}"
                )

    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "features": {
            "has_suspicious_keywords": has_suspicious_keywords,
            "has_links": has_links,
            "has_urgency_language": has_urgency_language,
            "has_credential_request": has_credential_request,
            "has_sender_mismatch": has_sender_mismatch,
        }
    }
