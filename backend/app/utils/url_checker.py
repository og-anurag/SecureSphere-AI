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
    ".tk",
]


def check_url(url: str):
    score = 0
    reasons = []

    features = {
    "uses_https": False,
    "uses_ip_address": False,
    "has_suspicious_tld": False,
    "has_at_symbol": False,
    "has_many_subdomains": False,
    "has_long_domain": False,
}

    parsed = urlparse(url)

    # Check HTTPS
    if parsed.scheme == "https":
        features["uses_https"] = True
    else:
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
            features["uses_ip_address"] = True
            score += 30
            reasons.append("Uses an IP address instead of a domain")
    # Check suspicious TLD
    if hostname:
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                features["has_suspicious_tld"] = True
                score += 15
                reasons.append(f"Uses suspicious top-level domain: {tld}")

    # Check long domain
    if hostname and len(hostname) > 30:
        features["has_long_domain"] = True
        score += 10
        reasons.append("Very long domain name")
    
    # Check for @ symbol
    if "@" in url:
        features["has_at_symbol"] = True
        score += 20
        reasons.append("URL contains @ symbol")  
    # Check for too many subdomains
    if hostname and not features["uses_ip_address"]:
        subdomain_count = hostname.count(".")

        if subdomain_count >= 3:
            features["has_many_subdomains"] = True
            score += 10
            reasons.append("URL contains many subdomains") 
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
    "features": features
}