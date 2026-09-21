import ipaddress
import re
from urllib.parse import urlparse

from app.utils.threat_intel import check_google_safe_browsing


# ---------------------------------------------------------
# Known brands for basic typosquatting detection
# ---------------------------------------------------------

KNOWN_BRANDS = [
    "paypal",
    "google",
    "microsoft",
    "amazon",
    "sbi",
    "hdfc",
    "icici",
    "netflix",
    "facebook",
    "instagram",
    "apple",
    "whatsapp",
    "flipkart",
    "phonepe",
    "paytm",
    "linkedin",
    "github",
]


# ---------------------------------------------------------
# Suspicious URL indicators
# ---------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "account",
    "password",
    "credential",
    "wallet",
    "payment",
    "bank",
    "banking",
    "otp",
    "pin",
    "free",
    "gift",
    "bonus",
    "reward",
    "claim",
    "urgent",
    "suspend",
    "suspended",
    "unlock",
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


# ---------------------------------------------------------
# Helper functions
# ---------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Return the Levenshtein edit distance between two strings."""

    if len(a) < len(b):
        return _levenshtein(b, a)

    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)

    for i, char_a in enumerate(a):
        current_row = [i + 1]

        for j, char_b in enumerate(b):
            current_row.append(
                min(
                    previous_row[j + 1] + 1,
                    current_row[j] + 1,
                    previous_row[j] + (char_a != char_b),
                )
            )

        previous_row = current_row

    return previous_row[-1]


def _looks_like_typosquat(domain: str) -> str | None:
    """
    Return the brand name that the domain resembles.

    This is a heuristic only. It should be treated as a signal,
    not proof that a domain is malicious.
    """

    domain_core = domain.split(".")[0].lower()

    tokens = {
        domain_core,
        *re.split(r"[-.]", domain_core),
    }

    for token in tokens:
        if len(token) <= 3:
            continue

        for brand in KNOWN_BRANDS:
            if token != brand and _levenshtein(token, brand) <= 2:
                return brand

    return None


def _is_ip_address(hostname: str | None) -> bool:
    """Return True when hostname is an IPv4 or IPv6 address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _has_punycode(hostname: str | None) -> bool:
    """Detect internationalized domains represented using xn--."""

    if not hostname:
        return False

    return any(
        label.lower().startswith("xn--")
        for label in hostname.split(".")
    )


def _has_encoded_characters(url: str) -> bool:
    """Detect percent-encoded characters in the URL."""

    return bool(re.search(r"%[0-9a-fA-F]{2}", url))


def _has_hexadecimal_ip(hostname: str | None) -> bool:
    """
    Detect a hexadecimal-looking hostname.

    This is only a heuristic and does not replace proper URL parsing.
    """

    if not hostname:
        return False

    hostname = hostname.lower()

    return bool(
        re.fullmatch(r"0x[0-9a-f]+", hostname)
        or re.fullmatch(r"[0-9a-f]{8,}", hostname)
    )


# ---------------------------------------------------------
# Main URL scanner
# ---------------------------------------------------------

def check_url(url: str):
    """
    Analyze a URL using local heuristics and external threat intelligence.

    The scanner returns:
        url
        score
        risk
        reasons
        features

    Google Safe Browsing is intentionally NOT added directly to the score.
    The unified risk/adapter layer owns external threat-intelligence
    score escalation to avoid double-counting.
    """

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
        "has_suspicious_keywords": False,
        "has_punycode": False,
        "has_encoded_characters": False,
        "has_hexadecimal_ip": False,
        "has_nonstandard_port": False,
        "has_userinfo": False,
        "has_fragment": False,
        "has_long_path": False,
        "has_query_parameters": False,
    }

    # -----------------------------------------------------
    # Basic URL parsing
    # -----------------------------------------------------

    parsed = urlparse(url)

    hostname = parsed.hostname

    # -----------------------------------------------------
    # HTTPS
    # -----------------------------------------------------

    if parsed.scheme.lower() == "https":
        features["uses_https"] = True
    else:
        score += 20
        reasons.append("URL does not use HTTPS")

    # -----------------------------------------------------
    # Suspicious keywords
    # -----------------------------------------------------

    url_lower = url.lower()

    matched_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            matched_keywords.append(keyword)
            score += 10
            reasons.append(
                f"Contains suspicious keyword: {keyword}"
            )

    if matched_keywords:
        features["has_suspicious_keywords"] = True

    # -----------------------------------------------------
    # IP address
    # -----------------------------------------------------

    if _is_ip_address(hostname):
        features["uses_ip_address"] = True
        score += 30
        reasons.append(
            "Uses an IP address instead of a domain"
        )

    # -----------------------------------------------------
    # Suspicious TLD
    # -----------------------------------------------------

    if hostname:
        hostname_lower = hostname.lower()

        for tld in SUSPICIOUS_TLDS:
            if hostname_lower.endswith(tld):
                features["has_suspicious_tld"] = True
                score += 15
                reasons.append(
                    f"Uses suspicious top-level domain: {tld}"
                )
                break

    # -----------------------------------------------------
    # Long domain
    # -----------------------------------------------------

    if hostname and len(hostname) > 30:
        features["has_long_domain"] = True
        score += 10
        reasons.append(
            "Very long domain name"
        )

    # -----------------------------------------------------
    # @ symbol / user information
    # -----------------------------------------------------

    if "@" in url:
        features["has_at_symbol"] = True
        features["has_userinfo"] = True

        score += 20
        reasons.append(
            "URL contains @ symbol"
        )

    # -----------------------------------------------------
    # Too many subdomains
    # -----------------------------------------------------

    if hostname and not features["uses_ip_address"]:
        subdomain_count = hostname.count(".")

        if subdomain_count >= 3:
            features["has_many_subdomains"] = True
            score += 10
            reasons.append(
                "URL contains many subdomains"
            )

    # -----------------------------------------------------
    # Typosquatting
    # -----------------------------------------------------

    if hostname and not features["uses_ip_address"]:
        brand = _looks_like_typosquat(hostname)

        if brand:
            features["is_typosquat"] = True
            score += 25

            reasons.append(
                f"Domain closely resembles the brand "
                f"'{brand}' (possible typosquat)"
            )

    # -----------------------------------------------------
    # Punycode / IDN
    # -----------------------------------------------------

    if _has_punycode(hostname):
        features["has_punycode"] = True
        score += 15
        reasons.append(
            "Domain uses Punycode/IDN encoding"
        )

    # -----------------------------------------------------
    # Percent encoding
    # -----------------------------------------------------

    if _has_encoded_characters(url):
        features["has_encoded_characters"] = True
        score += 5
        reasons.append(
            "URL contains percent-encoded characters"
        )

    # -----------------------------------------------------
    # Hexadecimal-looking hostname
    # -----------------------------------------------------

    if _has_hexadecimal_ip(hostname):
        features["has_hexadecimal_ip"] = True
        score += 15
        reasons.append(
            "Hostname has a hexadecimal-looking pattern"
        )

    # -----------------------------------------------------
    # Non-standard port
    # -----------------------------------------------------

    if parsed.port is not None:
        if parsed.port not in (80, 443):
            features["has_nonstandard_port"] = True
            score += 10
            reasons.append(
                f"Uses non-standard port: {parsed.port}"
            )

    # -----------------------------------------------------
    # Fragment
    # -----------------------------------------------------

    if parsed.fragment:
        features["has_fragment"] = True
        reasons.append(
            "URL contains a fragment"
        )

    # -----------------------------------------------------
    # Long path
    # -----------------------------------------------------

    if len(parsed.path) > 80:
        features["has_long_path"] = True
        score += 5
        reasons.append(
            "URL contains an unusually long path"
        )

    # -----------------------------------------------------
    # Query parameters
    # -----------------------------------------------------

    if parsed.query:
        features["has_query_parameters"] = True

        # Query strings are not inherently malicious,
        # so they do not increase the score by themselves.
        reasons.append(
            "URL contains query parameters"
        )

    # -----------------------------------------------------
    # Google Safe Browsing
    # -----------------------------------------------------

    safe_browsing = check_google_safe_browsing(url)

    if safe_browsing.get("flagged"):
        reasons.append(
            "Google Safe Browsing flagged this URL"
        )

    features["google_safe_browsing"] = safe_browsing

    # -----------------------------------------------------
    # Cap local heuristic score
    # -----------------------------------------------------

    score = min(score, 100)

    # -----------------------------------------------------
    # Risk classification
    # -----------------------------------------------------

    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    # -----------------------------------------------------
    # Final result
    # -----------------------------------------------------

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "reasons": reasons,
        "features": features,
    }