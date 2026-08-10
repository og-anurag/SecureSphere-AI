from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "account",
    "password",
    "free",
    "gift",
    "paypal",
]
SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".zip",
    ".country",
    ".gq",
]


def check_url(url: str):
    score = 0
    reasons = []

    parsed = urlparse(url)

    # Check HTTPS
    if parsed.scheme != "https":
        score += 20
        reasons.append("URL does not use HTTPS")

    # Check suspicious keywords
    url_lower = url.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            score += 10
            reasons.append(f"Contains suspicious keyword: {keyword}")

    # Check IP address in URL
    hostname = parsed.hostname

    if hostname:
        parts = hostname.split(".")
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            score += 30
            reasons.append("Uses an IP address instead of a domain")
    # Check suspicious TLD
    if hostname:
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                 score += 15
                 reasons.append(f"Uses suspicious top-level domain: {tld}")

    # Check long domain
    if hostname and len(hostname) > 30:
         score += 10
         reasons.append("Very long domain name")
    # Risk Level
    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "reasons": reasons,
   
     
    }