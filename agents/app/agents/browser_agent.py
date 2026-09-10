import re
from datetime import datetime, timezone
from urllib.parse import urlparse
from app.state import SecurityState
from app.threat_intel import check_google_safe_browsing, check_virustotal_url

# A tiny sample of commonly-impersonated brands for typosquat checking.
# Expand this list (or replace with a real brand-similarity model) as you go.
KNOWN_BRANDS = ["paypal", "google", "microsoft", "amazon", "sbi", "hdfc", "icici", "netflix"]


def _looks_like_typosquat(domain: str) -> bool:
    domain_core = domain.split(".")[0].lower()
    for brand in KNOWN_BRANDS:
        if domain_core != brand and _levenshtein(domain_core, brand) <= 2 and len(domain_core) > 3:
            return True
    return False


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


def browser_agent_node(state: SecurityState) -> SecurityState:
    url = re.search(r"https?://[^\s]+", state["raw_input"]).group(0)
    parsed = urlparse(url)
    domain = parsed.netloc

    findings = state.setdefault("findings", [])

    # 1. Typosquatting heuristic (free, instant)
    if _looks_like_typosquat(domain):
        findings.append({
            "agent": "browser_agent",
            "signal": "possible_typosquat",
            "detail": f"Domain '{domain}' closely resembles a known brand name.",
            "severity": "medium",
        })

    # 2. HTTPS check
    if parsed.scheme != "https":
        findings.append({
            "agent": "browser_agent",
            "signal": "no_https",
            "detail": "Site does not use HTTPS.",
            "severity": "low",
        })

    # 3. Google Safe Browsing
    gsb = check_google_safe_browsing(url)
    if gsb.get("flagged"):
        findings.append({
            "agent": "browser_agent",
            "signal": "google_safe_browsing_flagged",
            "detail": "Google Safe Browsing has flagged this URL.",
            "severity": "high",
        })

    # 4. VirusTotal
    vt = check_virustotal_url(url)
    if vt.get("flagged"):
        findings.append({
            "agent": "browser_agent",
            "signal": "virustotal_flagged",
            "detail": f"VirusTotal vendors flagged this URL: {vt.get('stats')}",
            "severity": "high",
        })

    return state
