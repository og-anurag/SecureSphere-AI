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

def check_email(sender: str, subject: str, body: str):
    score = 0
    reasons = []

    has_suspicious_keywords = False
    has_links = False

    text = f"{subject} {body}".lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            has_suspicious_keywords = True
            score += 10
            reasons.append(f"Contains suspicious keyword: {keyword}")

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
            "has_links": has_links
        }
    }       