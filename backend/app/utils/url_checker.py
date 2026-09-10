import re
from urllib.parse import urlparse


KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "amazon", "sbi", "hdfc",
    "icici", "netflix", "facebook", "instagram", "apple", "whatsapp",
]


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        cur_row = [i + 1]
        for j, cb in enumerate(b):
            cur_row.append(min(prev_row[j + 1] + 1, cur_row[j] + 1, prev_row[j] + (ca != cb)))
        prev_row = cur_row
    return prev_row[-1]


def _looks_like_typosquat(domain: str) -> str | None:
    """Returns the brand name it resembles, or None. Checks the registrable
    label and any hyphen/dot-separated tokens within it against known brands."""
    domain_core = domain.split(".")[0].lower()
    tokens = {domain_core, *re.split(r"[-.]", domain_core)}
    for token in tokens:
        if len(token) <= 3:
            continue
        for brand in KNOWN_BRANDS:
            if token != brand and _levenshtein(token, brand) <= 2:
                return brand
    return None


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
    "is_typosquat": False,
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
    # Check typosquatting against known brands
    if hostname:
        brand = _looks_like_typosquat(hostname)
        if brand:
            features["is_typosquat"] = True
            score += 25
            reasons.append(f"Domain closely resembles the brand '{brand}' (possible typosquat)")

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
